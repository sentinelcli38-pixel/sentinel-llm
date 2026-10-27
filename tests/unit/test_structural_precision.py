import copy
import json
import math

import pytest

from sentinel.modeling.properties import property_messages
from training import structural_precision as sp


def fixture():
    source = "contract Example { function f() public {} }"
    source_hash = sp.gp.sha(source.encode())
    key = sp.gp.sha(f"{source_hash}:Example".encode())
    expected = {"key": key, "source": source, "source_sha256": source_hash, "contract": "Example"}
    record = {"key": key, "source_sha256": source_hash, "contract": "Example", "status": "parsed",
              "features": {"extraction.parsed": 1, "count": 2}, "scoped_source": source,
              "target_spans": [], "unresolved_bases": [], "diagnostic": None}
    row = {"id": "fixture", "task": "swc_property", "swc": "104", "contract": "Example", "source_hash": source_hash,
           "messages": [*property_messages(source, "104", "Example"),
                        {"role": "assistant", "content": json.dumps({"swc": "104", "vulnerable": False})}]}
    cache = {"records": {key: record}, "row_keys": {row["id"]: key}}
    return expected, record, row, cache


def test_fixed_candidate_catalog_keeps_scoped_lexical_and_structural_controls():
    catalog = sp.catalog()
    assert len(catalog) == len({c["id"] for c in catalog}) == 18
    assert {c["representation"] for c in catalog} == {"ast_tree", "scoped_tokens", "ast_and_tokens"}
    assert {c["min_samples_leaf"] for c in catalog if c["representation"] == "ast_tree"} == {1, 3, 8}
    assert {c["C"] for c in catalog if c["representation"] != "ast_tree"} == {0.1, 1.0, 10.0}
    assert sp.PLAN["target_precision"] == 0.99 and sp.PLAN["minimum_recall"] == 0.8


@pytest.mark.parametrize("mode", ["key", "hash", "contract", "status", "source", "empty_features", "nan", "inf", "bool", "negative", "flag"])
def test_malformed_feature_records_are_rejected(mode):
    expected, record, _, _ = fixture()
    if mode in {"key", "contract", "status"}:
        record[mode] = "wrong"
    elif mode == "hash":
        record["source_sha256"] = "0" * 64
    elif mode == "source":
        record["scoped_source"] = ""
    elif mode == "empty_features":
        record["features"] = {}
    elif mode == "flag":
        record["features"]["extraction.parsed"] = 0
    else:
        record["features"]["count"] = {"nan": math.nan, "inf": math.inf, "bool": True, "negative": -1}[mode]
    with pytest.raises(ValueError, match="features"):
        sp.validate_features(record, expected)


@pytest.mark.parametrize("status", ["parse_error", "parser_internal_error", "target_missing", "target_ambiguous"])
def test_failures_preserve_whole_source_instead_of_disappearing_or_becoming_clean(status):
    expected, record, _, _ = fixture()
    record["status"], record["features"] = status, {f"extraction.{status}": 1}
    sp.validate_features(record, expected)
    record["scoped_source"] = "contract Replacement {}"
    with pytest.raises(ValueError, match="fallback"):
        sp.validate_features(record, expected)


def test_cache_requires_exact_cohort_and_source_target_alignment():
    _, record, row, cache = fixture()
    assert sp.records_for([row], cache) == [record]
    changed = copy.deepcopy(cache)
    changed["row_keys"]["unrelated"] = record["key"]
    with pytest.raises(ValueError, match="cohort"):
        sp.records_for([row], changed)
    changed = copy.deepcopy(cache)
    changed["row_keys"][row["id"]] = "wrong-key"
    with pytest.raises(ValueError, match="identity"):
        sp.records_for([row], changed)


def test_missing_fit_receipt_cannot_open_validation(tmp_path, monkeypatch):
    monkeypatch.setattr(sp, "load_training", lambda _: ({}, []))
    monkeypatch.setattr(sp.gp, "read_development", lambda _: pytest.fail("Premature validation read"))
    with pytest.raises(FileNotFoundError):
        sp.evaluate_frozen(tmp_path)


def test_numerically_indistinguishable_scores_are_tied_consistently_before_threshold_selection():
    scores = sp.stable_scores([1.0, math.nextafter(1.0, 0.0), 0.1, 0.2])
    assert scores == [1.0, 1.0, 0.1, 0.2]
    selected = sp.gp.choose_threshold([True, True, False, False], scores)
    assert selected["point_target_feasible"]
    assert selected["precision"] == selected["recall"] == 1
    assert sp.stable_scores([1 + 1e-15, -1e-15]) == [1.0, 0.0]


@pytest.mark.parametrize("value", [math.nan, math.inf, -0.1, 1.1, True])
def test_unusable_scores_are_not_hidden_by_rounding(value):
    with pytest.raises(ValueError, match="scores"):
        sp.stable_scores([value])


def test_cli_requires_experimental_acknowledgement(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.argv", ["structural_precision.py", "fit", "--output", str(tmp_path)])
    with pytest.raises(SystemExit) as error:
        sp.main()
    assert error.value.code == 2
