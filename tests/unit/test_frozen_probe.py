import copy
import hashlib
import json

import pytest

from sentinel.modeling.properties import property_messages
from training.frozen_probe import (
    CODE,
    PLAN,
    ROOT,
    evaluate,
    file_hash,
    load_protocol,
    main,
    prepare,
    selected_rows,
    validate_receipt,
)


def row(key, truth, swc="104"):
    source = f"contract Example_{key} {{ function value() public pure returns(uint) {{return 1;}} }}"
    return {"id": key, "swc": swc, "contract": f"Example_{key}", "task": "swc_property",
            "source_hash": hashlib.sha256(source.encode()).hexdigest(), "project_group": key,
            "messages": [*property_messages(source, swc, f"Example_{key}"),
                         {"role": "assistant", "content": json.dumps({"swc": swc, "vulnerable": truth})}]}


def fixture_rows():
    return {"train": [row("train_p", True), row("train_n", False)],
            "valid": [row("valid_p", True), row("valid_n", False)]}


def selection(rows):
    return {"train_ids": [r["id"] for r in rows["train"]], "valid_ids": [r["id"] for r in rows["valid"]],
            "train": {"selected": 2, "unique": 2, "per_bucket": {"104:true": 1, "104:false": 1}},
            "valid": {"selected": 2, "unique": 2, "per_bucket": {"104:true": 1, "104:false": 1}}}


def test_selection_retains_frozen_order_and_never_adds_unselected_data():
    rows = fixture_rows()
    frozen = selection(rows)
    rows["train"].append(row("extra", True))
    assert [r["id"] for r in selected_rows(rows, frozen)["train"]] == frozen["train_ids"]


@pytest.mark.parametrize("mode", ["duplicate", "missing", "count", "bucket", "overlap"])
def test_invalid_or_overlapping_selected_cohorts_fail_closed(mode):
    rows = fixture_rows()
    frozen = selection(rows)
    if mode == "duplicate":
        frozen["train_ids"][0] = frozen["train_ids"][1]
    elif mode == "missing":
        frozen["valid_ids"][0] = "absent"
    elif mode == "count":
        frozen["train"]["unique"] = 0
    elif mode == "bucket":
        frozen["valid"]["per_bucket"]["104:true"] = 0
    else:
        rows["valid"] = copy.deepcopy(rows["train"])
        frozen["valid_ids"] = frozen["train_ids"]
    with pytest.raises(ValueError):
        selected_rows(rows, frozen)


def test_classifier_metrics_count_misses_and_use_fixed_threshold_negative_ties():
    rows = fixture_rows()["valid"]
    negative = evaluate(rows, {r["id"]: 0.0 for r in rows})
    assert negative["scores"]["precision"] is None
    assert negative["scores"]["fn"] == 1
    assert negative["scores"]["recall"] == 0
    assert negative["pair_ordering"]["pair_ordering_score"] == 0.5
    positive = evaluate(rows, {r["id"]: 2.0 for r in rows})
    assert positive["scores"]["precision"] == 0.5
    assert positive["scores"]["fp"] == 1
    correct = evaluate(rows, {"valid_p": 2.0, "valid_n": -2.0})
    assert correct["scores"]["precision"] == 1
    assert correct["precision_interval"]["lower"] < 0.99
    assert correct["pair_ordering"]["pair_ordering_score"] == 1


@pytest.mark.parametrize("margins", [{}, {"valid_p": 1.0}, {"valid_p": 1.0, "valid_n": 2.0, "extra": 1.0},
                                    {"valid_p": float("nan"), "valid_n": 0.0}, {"valid_p": True, "valid_n": 0.0}])
def test_missing_extra_or_invalid_margins_cannot_disappear(margins):
    with pytest.raises(ValueError):
        evaluate(fixture_rows()["valid"], margins)


@pytest.fixture
def receipt(tmp_path):
    (tmp_path / "protocol.json").write_bytes(b"unit protocol")
    (tmp_path / "features.npz").write_bytes(b"unit fixture only, not a feature archive")
    rows = fixture_rows()
    return rows, {"protocol_sha256": hashlib.sha256(b"unit protocol").hexdigest(),
                  "features_sha256": hashlib.sha256(b"unit fixture only, not a feature archive").hexdigest(),
                  "ids": {split: [r["id"] for r in items] for split, items in rows.items()},
                  "shapes": {split: [2, PLAN["hidden_size"]] for split in rows},
                  "token_lengths": {split: [100, 100] for split in rows},
                  "base_parameter_count": 1543714304, "base_weights_updated": False,
                  "reserved_test_accessed": False,
                  "validation_logit_reproduction": {"passed": True, "atol": 0.05, "rtol": 0.01}}


def test_receipt_binds_complete_order_dimensions_and_feature_bytes(tmp_path, receipt):
    rows, document = receipt
    validate_receipt(tmp_path, rows, document)
    for mutate in (lambda d: d["ids"]["valid"].reverse(),
                   lambda d: d["shapes"].update(valid=[1, 1536]),
                   lambda d: d.update(base_weights_updated=True),
                   lambda d: d.update(features_sha256="f" * 64),
                   lambda d: d["token_lengths"].update(valid=[100, 1024]),
                   lambda d: d["token_lengths"].update(valid=[100, True])):
        changed = copy.deepcopy(document)
        mutate(changed)
        with pytest.raises(ValueError):
            validate_receipt(tmp_path, rows, changed)


def test_cli_requires_explicit_experimental_opt_in(tmp_path, monkeypatch):
    for action in ("extract", "score"):
        monkeypatch.setattr("sys.argv", ["probe", action, "--output", str(tmp_path)])
        with pytest.raises(SystemExit, match="experimental"):
            main()


def test_preparation_preserves_existing_outputs_and_frozen_input_boundaries(tmp_path):
    existing = tmp_path / "existing"
    existing.mkdir()
    (existing / "keep").write_text("untouched")
    with pytest.raises(FileExistsError):
        prepare(tmp_path, tmp_path, tmp_path, existing)
    assert (existing / "keep").read_text() == "untouched"
    with pytest.raises(ValueError, match="outside"):
        prepare(tmp_path, tmp_path, tmp_path, tmp_path / "new")


@pytest.mark.parametrize("mode", ["valid", "code", "source_evidence", "dataset", "plan"])
def test_frozen_protocol_revalidates_implementation_inputs_and_source_evidence(tmp_path, monkeypatch, mode):
    rows = fixture_rows()
    source = tmp_path / "original-report.json"
    source.write_text("original report fixture")
    pins = {"reserved_test_accessed": False}
    document = {"plan": PLAN, "implementation_sha256": {name: file_hash(ROOT / name) for name in CODE},
                "source_run_pins": {str(source): file_hash(source)}, "dataset": str(tmp_path / "dataset"),
                "input_pins": pins, "selection": selection(rows)}
    monkeypatch.setattr("training.frozen_probe.read_development", lambda *args: (rows, pins))
    if mode == "code":
        document["implementation_sha256"][CODE[0]] = "f" * 64
    elif mode == "source_evidence":
        source.write_text("changed")
    elif mode == "dataset":
        document["input_pins"] = {"different": "dataset"}
    elif mode == "plan":
        document["plan"] = {**PLAN, "threshold": 0.99}
    (tmp_path / "protocol.json").write_text(json.dumps(document))
    if mode == "valid":
        _, result = load_protocol(tmp_path)
        assert result == rows
    else:
        with pytest.raises(ValueError):
            load_protocol(tmp_path)
