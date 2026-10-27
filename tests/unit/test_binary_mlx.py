import hashlib
import json
import math
from collections import Counter
from pathlib import Path

import pytest

from sentinel.modeling.properties import CGT_REVISION, PROPERTIES, property_messages
from training.binary_mlx import (
    PLAN,
    binary_nll,
    encode_row,
    main,
    probability,
    read_development,
    report_predictions,
    select_rows,
    source_and_target,
    wilson_interval,
    write_json,
)


def row(case_id="case", swc="107", vulnerable=False):
    source = f"contract Example_{case_id} {{ function value() public pure returns(uint) {{return 1;}} }}"
    return {"id": case_id, "swc": swc, "contract": f"Example_{case_id}", "task": "swc_property",
            "source_hash": hashlib.sha256(source.encode()).hexdigest(), "project_group": f"group-{case_id}",
            "lexical_fingerprint": f"fingerprint-{case_id}",
            "messages": [*property_messages(source, swc, f"Example_{case_id}"),
                         {"role": "assistant", "content": json.dumps({"swc": swc, "vulnerable": vulnerable})}]}


def dataset_fixture(tmp_path):
    for split in ("train", "valid"):
        (tmp_path / f"{split}.jsonl").write_text(json.dumps(row(split)) + "\n")
    manifest = {"source_revision": CGT_REVISION, "task": "swc_property",
                "split_counts": {split: 1 for split in ("train", "valid")},
                "split_sha256": {split: hashlib.sha256((tmp_path / f"{split}.jsonl").read_bytes()).hexdigest()
                                 for split in ("train", "valid")}}
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    return manifest


def test_reads_only_train_and_valid_never_reserved_files(tmp_path, monkeypatch):
    dataset_fixture(tmp_path)
    original = Path.read_bytes

    def guard(path):
        assert path.name != "test.jsonl"
        return original(path)
    monkeypatch.setattr(Path, "read_bytes", guard)
    splits, pins = read_development(tmp_path)
    assert set(splits) == {"train", "valid"}
    assert set(pins["split_sha256"]) == {"train", "valid"}
    assert pins["reserved_test_accessed"] is False


@pytest.mark.parametrize("field", ["id", "source_hash", "project_group", "lexical_fingerprint"])
def test_cross_split_overlap_is_rejected(tmp_path, field):
    manifest = dataset_fixture(tmp_path)
    train = row("train")
    valid = row("valid")
    valid[field] = train[field]
    (tmp_path / "valid.jsonl").write_text(json.dumps(valid) + "\n")
    manifest["split_sha256"]["valid"] = hashlib.sha256((tmp_path / "valid.jsonl").read_bytes()).hexdigest()
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        read_development(tmp_path)


def test_changed_dataset_bytes_and_wrong_source_pin_are_rejected(tmp_path):
    dataset_fixture(tmp_path)
    (tmp_path / "train.jsonl").write_text("changed\n")
    with pytest.raises(ValueError, match="Changed train"):
        read_development(tmp_path)
    case = row()
    case["source_hash"] = "0" * 64
    with pytest.raises(ValueError, match="source"):
        source_and_target(case)


@pytest.mark.parametrize("mode", ["task", "system", "scope", "swc", "label", "role"])
def test_prompt_and_target_scope_are_validated(mode):
    case = row()
    if mode == "task":
        case["task"] = "findings"
    elif mode == "system":
        case["messages"][0]["content"] = "different"
    elif mode == "scope":
        case["contract"] = "Different"
    elif mode == "swc":
        case["swc"] = "104"
    elif mode == "label":
        case["messages"][-1]["content"] = '{"swc":"107","vulnerable":"false"}'
    elif mode == "role":
        case["messages"][-1]["role"] = "user"
    with pytest.raises(ValueError):
        source_and_target(case)


def test_model_prompt_never_contains_supervised_answer():
    class Tokenizer:
        def apply_chat_template(self, messages, **kwargs):
            assert [message["role"] for message in messages] == ["system", "user"]
            assert "Return only JSON" not in messages[0]["content"]
            return "prompt only"

        def encode(self, prompt, **kwargs):
            assert prompt == "prompt only"
            return [1, 2, 3]
    encoded = encode_row(row(vulnerable=True), Tokenizer())
    assert encoded["tokens"] == [1, 2, 3]
    assert encoded["vulnerable"] is True


def selection_pool():
    return [{"id": f"{swc}-{truth}-{index}", "swc": swc, "vulnerable": truth, "tokens": [1] * 10}
            for swc in PROPERTIES for truth in (False, True) for index in range(3 if truth else 9)]


def test_training_balances_each_property_without_repeating_minority_rows():
    selected, metadata = select_rows(selection_pool(), training=True)
    assert len(selected) == metadata["unique"] == 24
    assert set(metadata["per_bucket"].values()) == {3}
    assert not metadata["oversampling"]
    assert select_rows(selection_pool(), training=True)[0] == selected


def test_overlength_rows_are_excluded_whole_and_validation_is_not_oversampled():
    pool = selection_pool()
    pool[0]["tokens"] = [1] * PLAN["max_tokens"]
    selected, metadata = select_rows(pool, training=False)
    assert pool[0]["id"] not in {case["id"] for case in selected}
    assert sum(metadata["overlength_excluded"].values()) == 1
    assert not metadata["truncation"]
    assert max(Counter(case["id"] for case in selected).values()) == 1


def test_training_refuses_missing_labels_and_duplicate_ids():
    with pytest.raises(ValueError, match="Both training labels"):
        select_rows([case for case in selection_pool() if not case["vulnerable"]], training=True)
    pool = selection_pool()
    with pytest.raises(ValueError, match="Duplicate"):
        select_rows([*pool, pool[0]], training=True)


def test_logit_score_is_not_an_empirical_precision_claim():
    rows = [{"id": "positive", "swc": "107", "vulnerable": True,
             "expected": '{"swc":"107","vulnerable":true}'},
            {"id": "negative", "swc": "107", "vulnerable": False,
             "expected": '{"swc":"107","vulnerable":false}'}]
    result = report_predictions(rows, [[0, 10], [0, 10]])
    assert result["scores"]["precision"] == 0.5
    assert result["scores"]["fp"] == 1
    assert result["predictions"][1]["conditional_true_score"] > 0.99
    assert result["precision_interval"]["lower"] < 0.99
    with pytest.raises(ValueError):
        report_predictions(rows, [[0, 10]])


def test_all_negative_predictions_have_no_precision_not_perfect_precision():
    case = {"id": "positive", "swc": "107", "vulnerable": True,
            "expected": '{"swc":"107","vulnerable":true}'}
    result = report_predictions([case], [[0, 0]])
    assert result["scores"]["precision"] is None
    assert result["scores"]["recall"] == 0


def test_precision_interval_does_not_turn_a_small_perfect_sample_into_99_percent_evidence():
    assert wilson_interval(0, 0)["lower"] is None
    assert wilson_interval(10, 10)["lower"] == pytest.approx(0.7224672001371107)
    assert wilson_interval(100, 100)["lower"] < 0.99
    with pytest.raises(ValueError):
        wilson_interval(True, 10)


def test_boolean_loss_is_stable_and_rewards_correct_discrimination():
    rows = [{"vulnerable": True}, {"vulnerable": False}]
    assert binary_nll(rows, [[0, 0], [0, 0]]) == pytest.approx(math.log(2))
    assert binary_nll(rows, [[0, 10], [10, 0]]) < 0.001
    assert binary_nll(rows, [[10, 0], [0, 10]]) > 9
    assert probability([0, 1000]) == 1
    assert probability([1000, 0]) == 0
    with pytest.raises(ValueError):
        binary_nll(rows, [])


@pytest.mark.parametrize("values", [[float("nan"), 1], [0, float("inf")], [1], [1e308, -1e308]])
def test_nonfinite_or_malformed_logits_are_not_scored(values):
    with pytest.raises(ValueError):
        probability(values)


def test_existing_run_and_evidence_files_cannot_be_overwritten(tmp_path, monkeypatch):
    path = tmp_path / "report.json"
    write_json(path, {"keep": True})
    with pytest.raises(FileExistsError):
        write_json(path, {})
    monkeypatch.setattr("sys.argv", ["binary", "--output", str(tmp_path)])
    with pytest.raises(FileExistsError):
        main()
    assert json.loads(path.read_text()) == {"keep": True}
