import csv
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel.modeling.clones import clone_components, lexical_fingerprint
from sentinel.modeling.data import audit_dataset
from sentinel.modeling.properties import (
    CGT_REVISION,
    PROPERTIES,
    balanced_training,
    evaluation_subset,
    prepare_properties,
)
from sentinel.modeling.property_scoring import (
    parse_property,
    property_baselines,
    score_properties,
    validation_gate,
)


def row(identifier: str, swc: str, vulnerable: bool) -> dict:
    return {"id": identifier, "messages": [{"role": "assistant", "content": json.dumps({"swc": swc, "vulnerable": vulnerable})}]}


def test_clones_ignore_names_comments_literals_and_compiler_version() -> None:
    first = "pragma solidity ^0.8.20; contract A { uint public x = 3; function a() public { require(x > 1); } }"
    second = "pragma solidity ^0.4.24; /* annotated */ contract B { uint public y = 9; function b() public { require(y > 4); } }"
    unrelated = "contract C { function f() public payable { selfdestruct(payable(msg.sender)); } }"
    assert lexical_fingerprint(first) == lexical_fingerprint(second)
    groups, _ = clone_components({"a": first, "b": second, "c": unrelated}, {})
    assert groups["a"] == groups["b"]
    assert groups["a"] != groups["c"]


def test_identity_links_are_transitive() -> None:
    groups, _ = clone_components({"a": "contract A {}", "b": "library B {}", "c": "interface C {}"},
                                 {"a": ["address:x"], "b": ["address:x", "runtime:y"], "c": ["runtime:y"]})
    assert len(set(groups.values())) == 1


def test_training_balances_only_available_examples_and_reports_repetition() -> None:
    rows = [row(f"{swc}:{label}", swc, label) for swc in PROPERTIES for label in (True, False)]
    selected, summary = balanced_training(rows, 3, 42)
    assert len(selected) == 24
    assert summary["unique_selected"] == 8
    assert set(summary["selected"].values()) == {3}
    assert selected == balanced_training(rows, 3, 42)[0]
    assert len(evaluation_subset(rows, 3, 42)) == 8
    with pytest.raises(ValueError, match="Missing training buckets"):
        balanced_training(rows[:-1], 3, 42)


@pytest.mark.parametrize("prediction", [
    '{"swc":"107","vulnerable":"false"}',
    '{"swc":"107","vulnerable":0}',
    '{"swc":"107","vulnerable":false,"confidence":0.9}',
    '{"swc":"999","vulnerable":false}',
    '{"swc":"104","vulnerable":false}',
    '{"swc":["107"],"vulnerable":false}',
])
def test_property_parser_rejects_coercion_and_wrong_assessment(prediction: str) -> None:
    with pytest.raises(ValueError):
        parse_property(prediction, "107")


def test_invalid_output_never_counts_as_true_negative() -> None:
    results = []
    for index, (expected, prediction) in enumerate([(True, True), (True, False), (False, True), (False, False), (True, None), (False, None)]):
        results.append({"id": str(index), "expected": row("x", "107", expected)["messages"][-1]["content"],
                        "prediction": "Not sure" if prediction is None else row("x", "107", prediction)["messages"][-1]["content"]})
    scores = score_properties(results)
    assert scores["cases"] == 6
    assert scores["tp"] == scores["fp"] == scores["tn"] == scores["fn"] == 1
    assert scores["invalid_positive"] == scores["invalid_negative"] == 1
    assert scores["accuracy"] == pytest.approx(1 / 3)
    assert scores["specificity"] == pytest.approx(1 / 3)
    assert scores["recall"] == pytest.approx(1 / 3)
    assert scores["negative_error_rate"] == pytest.approx(2 / 3)


def test_baselines_use_training_labels_and_do_not_invent_clean_controls() -> None:
    train = [row(f"{swc}:t", swc, True) for swc in PROPERTIES]
    test = [row(f"{swc}:f", swc, False) for swc in PROPERTIES]
    baselines = property_baselines(train, test)
    assert baselines["training_majority"]["fp"] == 4
    assert baselines["always_negative"]["tn"] == 4
    assert baselines["always_positive"]["fp"] == 4


def test_gate_rejects_always_negative_even_with_high_accuracy() -> None:
    baselines = {"always_negative": {"accuracy": 0.9}}
    scores = {"accuracy": 0.9, "valid_rate": 1.0, "balanced_accuracy": 0.5, "recall": 0.0, "specificity": 1.0}
    gate = validation_gate(scores, baselines)
    assert not gate["passed"]
    assert "recall below 0.5" in gate["failures"]


def test_importer_preserves_scope_and_excludes_conflicting_labels(tmp_path: Path, monkeypatch) -> None:
    corpus = tmp_path / "cgt"
    (corpus / "source").mkdir(parents=True)
    previous = tmp_path / "prior"
    previous.mkdir()
    (previous / "vulnerabilities.json").write_text("[]")
    fields = ["dataset", "id", "property", "property_holds", "chain", "addr", "contractname", "fp_sol", "fp_sol2", "fp_bytecode", "fp_runtime", "swc", "dasp"]
    assessments = []
    for index in range(12):
        key = f"{index:032x}"
        (corpus / "source" / f"{key}.sol").write_text(f"contract C{index} {{ uint{8 * (index + 1)} public n; }}")
        item = dict.fromkeys(fields, "")
        item.update(dataset="example", id=str(index), property="Reentrancy", property_holds="f",
                    contractname=f"C{index}", fp_sol=key, fp_sol2=f"source{index}", swc="107")
        assessments.append(item)
    assessments.append({**assessments[0], "property_holds": "t"})
    with (corpus / "consolidated.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter=";")
        writer.writeheader()
        writer.writerows(assessments)
    monkeypatch.setattr("sentinel.modeling.properties.subprocess.run", lambda *args, **kwargs: SimpleNamespace(stdout=CGT_REVISION))
    output = tmp_path / "prepared"
    manifest = prepare_properties(corpus, previous, output)
    assert manifest["skipped"]["conflicting_property_labels"] == 1
    assert sum(manifest["split_counts"].values()) == 11
    assert audit_dataset(output)["status"] == "passed"
    with pytest.raises(ValueError, match="Output already exists"):
        prepare_properties(corpus, previous, output)
