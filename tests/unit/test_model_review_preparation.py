import copy
import hashlib
import json
from pathlib import Path

import pytest

from scripts.label_review import consensus
from sentinel.modeling.clones import lexical_fingerprint
from sentinel.modeling.properties import property_messages
from training.prepare_model_review import build, contrast_pairs, selected_training


def row(key, truth, swc="104", extra=""):
    source = f"contract Example_{key} {{ function pay(address a) public {{ {extra} a.send(1); }} }}"
    return {"id": key, "swc": swc, "contract": f"Example_{key}", "task": "swc_property",
            "source_hash": hashlib.sha256(source.encode()).hexdigest(), "project_group": key,
            "lexical_fingerprint": lexical_fingerprint(source), "source_url": "https://example.invalid/unit",
            "assessments": [{"dataset": "unit-only", "property_holds": str(truth)}],
            "messages": [*property_messages(source, swc, f"Example_{key}"),
                         {"role": "assistant", "content": json.dumps({"swc": swc, "vulnerable": truth})}]}


@pytest.fixture
def evidence(tmp_path, monkeypatch):
    run, dataset, output = (tmp_path / name for name in ("run", "dataset", "review"))
    run.mkdir()
    dataset.mkdir()
    training = [row("p1", True), row("n1", False, extra="require(a != address(0));"),
                row("p2", True, extra="uint x = 1;"), row("n2", False, extra="if(a == address(0)) return;")]
    valid = [row("v1", True, "107"), row("v2", False), row("v3", True, "101")]
    selection = {"train_ids": [item["id"] for item in training], "train": {
        "selected": 4, "unique": 4, "per_bucket": {"104:true": 2, "104:false": 2}}}
    path = run / "data-selection.json"
    path.write_text(json.dumps(selection))
    (run / "run.json").write_text(json.dumps({"trained_row_ids": ["p1"]}))
    pins = {"reserved_test_accessed": False}
    diagnostic = {"run": str(run), "training_input_pins": pins,
                  "input_pins": {str(path): hashlib.sha256(path.read_bytes()).hexdigest()}}
    monkeypatch.setattr("training.prepare_model_review.inspect", lambda *args: (
        diagnostic, {item["id"]: item for item in valid}, {}))
    monkeypatch.setattr("training.prepare_model_review.read_development", lambda *args: (
        {"train": training, "valid": valid}, pins))
    return run, dataset, output, training, valid, selection, diagnostic


def test_preparation_retains_every_validation_case_and_blinds_both_cohorts(evidence):
    run, dataset, output, training, valid, _, _ = evidence
    original = (run / "data-selection.json").read_bytes()
    result = build(run, dataset, output)
    assert result["validation_cases"] == len(valid)
    assert result["training_cases"] == len(training)
    assert result["reviews_completed"] == 0
    assert not any(result[key] for key in ("approved_for_training", "model_updated", "labels_changed",
                                          "reserved_test_accessed", "claim_99_percent_supported"))
    assert (run / "data-selection.json").read_bytes() == original
    for role, rows in (("validation", valid), ("training", training)):
        manifest = json.loads((output / f"{role}-manifest.json").read_text())
        assert {case["id"] for case in manifest["cases"]} == {item["id"] for item in rows}
        packet = json.loads((output / role / "blind/cases.json").read_text())
        assert "not verified compiled projects" in packet["scope"]
        assert "ground_truth" not in json.dumps(packet)
        assert "conditional_true_score" not in json.dumps(packet)
        assert not list((output / role / "blind").glob("*contrast*"))
        for case in manifest["cases"]:
            source = Path(case["project_path"]) / case["target_file"]
            assert hashlib.sha256(source.read_bytes()).hexdigest() == case["source_sha256"]
            assert case["provenance"]["original_assessments"]
            assert case["provenance"]["compilation"]["status"] == "not_attempted"
        for name in ("a", "b"):
            form = json.loads((output / role / f"blind/reviewer-{name}.json").read_text())
            assert form["reviewer"]["id"] == ""
            assert {item["decision"] for item in form["reviews"]} == {"pending"}
        with pytest.raises(ValueError, match="named human"):
            consensus(output / role, output / role / "blind/reviewer-a.json",
                      output / role / "blind/reviewer-b.json", output / f"{role}-reviewed")
    pairs = json.loads((output / "training-contrast-candidates.json").read_text())["pairs"]
    paired = [pair[key] for pair in pairs for key in ("historical_positive_id", "historical_negative_id")]
    assert len(paired) == len(set(paired)) == 4
    assert set(paired) <= {item["id"] for item in training}
    assert not set(paired) & {item["id"] for item in valid}
    for name, pin in result["artifact_sha256"].items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == pin


def test_existing_output_and_input_directories_cannot_be_used(evidence):
    run, dataset, output, *_ = evidence
    output.mkdir()
    (output / "keep").write_text("untouched")
    with pytest.raises(FileExistsError):
        build(run, dataset, output)
    assert (output / "keep").read_text() == "untouched"
    for directory in (run, dataset):
        with pytest.raises(ValueError, match="outside"):
            build(run, dataset, directory / "new-review")
        assert not (directory / "new-review").exists()


@pytest.mark.parametrize("mode", ["missing", "duplicate", "count", "unique", "bucket", "source", "fingerprint", "pin"])
def test_corrupt_preparation_evidence_fails_before_writes(evidence, mode):
    run, dataset, output, training, _, selection, diagnostic = evidence
    if mode == "missing":
        selection["train_ids"][0] = "absent"
    elif mode == "duplicate":
        selection["train_ids"][0] = selection["train_ids"][1]
    elif mode in {"count", "unique"}:
        selection["train"]["selected" if mode == "count" else "unique"] = 0
    elif mode == "bucket":
        selection["train"]["per_bucket"]["104:true"] = 8
    elif mode == "source":
        training[0]["source_hash"] = "f" * 64
    elif mode == "fingerprint":
        training[0]["lexical_fingerprint"] = "f" * 64
    elif mode == "pin":
        diagnostic["input_pins"][str(run / "data-selection.json")] = "f" * 64
    if mode in {"missing", "duplicate", "count", "unique", "bucket"}:
        path = run / "data-selection.json"
        path.write_text(json.dumps(selection))
        diagnostic["input_pins"][str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(ValueError):
        build(run, dataset, output)
    assert not output.exists()


def test_pairs_are_deterministic_and_leave_ineligible_cases_visible(evidence):
    *_, training, _, _, _ = evidence
    assert contrast_pairs(training) == contrast_pairs(list(reversed(training)))
    rows = [copy.deepcopy(training[0]), copy.deepcopy(training[1])]
    rows[1]["project_group"] = rows[0]["project_group"]
    result = contrast_pairs(rows)
    assert result["pairs"] == []
    assert set(result["unpaired_ids"]) == {item["id"] for item in rows}
    assert not result["approved_for_training"]


@pytest.mark.parametrize("mode", ["empty", "duplicate", "wrong_property", "single_label"])
def test_invalid_contrast_pools_are_rejected(evidence, mode):
    training = copy.deepcopy(evidence[3])
    if mode == "empty":
        training = []
    elif mode == "duplicate":
        training.append(training[0])
    elif mode == "wrong_property":
        training[0] = row("different", True, "107")
    else:
        training = [training[0], training[2]]
    with pytest.raises(ValueError):
        contrast_pairs(training)


def test_selected_training_does_not_expand_pool_or_use_validation(evidence):
    training, valid, selection = evidence[3:6]
    extra = row("not_selected", False)
    selected = selected_training({"train": [*training, extra], "valid": valid}, selection)
    assert {item["id"] for item in selected} == set(selection["train_ids"])
