import copy
import hashlib
import json
from pathlib import Path

import pytest

from sentinel.modeling.properties import property_messages
from training.binary_mlx import (
    PLAN,
    binary_nll,
    encode_row,
    report_predictions,
    source_and_target,
)
from training.diagnose_binary import (
    distribution,
    inspect,
    main,
    prompt_messages,
    ranking,
    sample_cases,
    verify_predictions,
)
from training.local_model import file_hash


def source_row(case_id, truth):
    source = f"contract Example_{case_id} {{ function value() public pure returns(uint) {{return 1;}} }}"
    return {"id": case_id, "swc": "107", "contract": f"Example_{case_id}", "task": "swc_property",
            "source_hash": hashlib.sha256(source.encode()).hexdigest(), "project_group": case_id,
            "messages": [*property_messages(source, "107", f"Example_{case_id}"),
                         {"role": "assistant", "content": json.dumps({"swc": "107", "vulnerable": truth})}]}


def scored_rows():
    return [{"id": key, "swc": "107", "vulnerable": value,
             "expected": json.dumps({"swc": "107", "vulnerable": value})}
            for key, value in (("positive", True), ("negative", False))]


def run_fixture(tmp_path, monkeypatch):
    run = tmp_path / "run"
    (run / "selected-adapter").mkdir(parents=True)
    (run / "adapter").mkdir()
    rows = scored_rows()
    report = report_predictions(rows, [[0, 1], [1, 0]])
    sources = {row["id"]: source_row(row["id"], row["vulnerable"]) for row in rows}
    pins = {"path": str(tmp_path), "reserved_test_accessed": False}
    monkeypatch.setattr("training.diagnose_binary.read_development", lambda path: (
        {"train": [source_row("train", False)], "valid": list(sources.values())}, pins))
    loss = binary_nll(rows, [[0, 1], [1, 0]])
    candidates = []
    for step in (16, 32, 48, 64):
        path = run / "adapter" / f"{step:07d}_adapters.safetensors"
        path.write_bytes(f"unit fixture, not weights: {step}".encode())
        candidates.append({"step": step, "checkpoint_sha256": file_hash(path), "boolean_validation_loss": loss})
        (run / f"validation-step-{step}.json").write_text(json.dumps(report))
    (run / "selected-adapter/adapters.safetensors").write_bytes((run / "adapter/0000016_adapters.safetensors").read_bytes())
    (run / "selected-adapter/adapter_config.json").write_text("{}")
    (run / "selected-adapter/selection.json").write_text(json.dumps({**candidates[0], "candidates": candidates}))
    (run / "base-validation.json").write_text(json.dumps(report))
    (run / "comparison.json").write_text(json.dumps({"selected_step": 16, "base": report["scores"], "adapted": report["scores"]}))
    (run / "data-selection.json").write_text(json.dumps({"input_pins": pins, "valid_ids": ["positive", "negative"],
                                                       "valid": {"selected": 2}, "train_ids": ["train"]}))
    (run / "run.json").write_text(json.dumps({"status": "completed", "plan": PLAN, "input_pins": pins,
        "implementation_sha256": file_hash(Path("training/binary_mlx.py")), "checkpoint_selection": candidates[0],
        "trained_row_ids": ["train"], "examples_seen": 1, "unique_examples_seen": 1}))
    return run, tmp_path, report


def test_pair_ranking_handles_ties_perfect_inverse_and_missing_classes():
    rows = scored_rows()
    correct = report_predictions(rows, [[0, 2], [2, 0]])["predictions"]
    assert ranking(correct)["pair_ordering_score"] == 1
    reverse = report_predictions(rows, [[2, 0], [0, 2]])["predictions"]
    assert ranking(reverse)["pair_ordering_score"] == 0
    tied = report_predictions(rows, [[0, 0], [0, 0]])["predictions"]
    assert ranking(tied)["pair_ordering_score"] == 0.5
    assert ranking(tied[:1])["pair_ordering_score"] is None


def test_distribution_rejects_empty_and_nonfinite_scores():
    assert distribution([1, 2, 3])["mean"] == 2
    for values in ([], [float("nan")], [float("inf")]):
        with pytest.raises(ValueError):
            distribution(values)


@pytest.mark.parametrize("mode", ["missing", "duplicate", "label", "score", "decision", "metrics", "nonfinite"])
def test_saved_prediction_tampering_is_rejected(mode):
    rows = scored_rows()
    report = report_predictions(rows, [[0, 2], [2, 0]])
    expected = {row["id"]: json.loads(row["expected"]) for row in rows}
    row = report["predictions"][0]
    if mode == "missing":
        report["predictions"].pop()
    elif mode == "duplicate":
        report["predictions"].append(copy.deepcopy(row))
    elif mode == "label":
        row["expected"] = '{"swc":"107","vulnerable":false}'
    elif mode == "score":
        row["conditional_true_score"] = 0.99
    elif mode == "decision":
        row["prediction"] = '{"swc":"107","vulnerable":false}'
    elif mode == "metrics":
        report["scores"]["precision"] = 0.99
    else:
        row["conditional_true_score"] = float("nan")
    with pytest.raises(ValueError):
        verify_predictions(report, ["positive", "negative"], expected)


def test_full_ablation_prompt_exactly_matches_training_prompt_and_excludes_answer():
    row = source_row("case", True)
    captured = []

    class Tokenizer:
        def apply_chat_template(self, messages, **kwargs):
            captured.append(messages)
            return "prompt"

        def encode(self, text, **kwargs):
            return [1, 2, 3]
    encode_row(row, Tokenizer())
    assert prompt_messages(row, "full") == captured[0]
    source, _ = source_and_target(row)
    assert source not in prompt_messages(row, "without_source")[1]["content"]
    assert row["contract"] not in prompt_messages(row, "property_only")[1]["content"]
    assert [message["role"] for message in prompt_messages(row, "full")] == ["system", "user"]


def test_sampling_is_bounded_deterministic_and_does_not_select_by_model_score():
    rows = {f"case_{i}_{truth}": source_row(f"case_{i}_{truth}", truth) for i in range(5) for truth in (True, False)}
    selected = sample_cases(rows)
    assert len(selected) == 4
    assert len({row["id"] for row in selected}) == 4
    assert sample_cases(dict(reversed(list(rows.items())))) == selected


def test_offline_diagnostic_verifies_reports_without_model_execution(tmp_path, monkeypatch):
    run, dataset, _ = run_fixture(tmp_path, monkeypatch)
    result, rows, saved = inspect(run, dataset)
    assert result["validation_cases"] == 2
    assert result["base"]["pair_ordering_score"] == 1
    assert result["adapted"]["pair_ordering_score"] == 1
    assert result["logit_margin_shift"]["mean"] == 0
    assert result["reserved_test_accessed"] is False
    assert not result["threshold_changed"] and not result["model_updated"]
    assert set(rows) == {"positive", "negative"} == set(saved["base"])


@pytest.mark.parametrize("mode", ["weights", "checkpoint", "choice", "loss", "nonfinite_loss", "input", "exposure", "comparison"])
def test_mixed_run_evidence_cannot_enter_diagnostic(tmp_path, monkeypatch, mode):
    run, dataset, _ = run_fixture(tmp_path, monkeypatch)
    if mode == "weights":
        (run / "selected-adapter/adapters.safetensors").write_bytes(b"changed")
    elif mode == "checkpoint":
        (run / "adapter/0000064_adapters.safetensors").write_bytes(b"changed")
    else:
        path = run / ("selected-adapter/selection.json" if mode in {"choice", "loss", "nonfinite_loss"} else "comparison.json" if mode == "comparison" else "run.json")
        value = json.loads(path.read_text())
        if mode == "choice":
            value["step"] = 64
        elif mode == "loss":
            value["candidates"][-1]["boolean_validation_loss"] = 0.01
        elif mode == "nonfinite_loss":
            value["candidates"][-1]["boolean_validation_loss"] = float("nan")
        elif mode == "input":
            value["input_pins"] = {}
        elif mode == "exposure":
            value["examples_seen"] = 99
        else:
            value["adapted"]["precision"] = 0.99
        path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        inspect(run, dataset)


def test_cli_requires_inference_opt_in_and_preserves_existing_output(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.argv", ["diagnose", "ablate", "--output", str(tmp_path / "report.json")])
    with pytest.raises(SystemExit, match="experimental"):
        main()
    path = tmp_path / "existing.json"
    path.write_text("preserve")
    monkeypatch.setattr("sys.argv", ["diagnose", "offline", "--output", str(path)])
    with pytest.raises(FileExistsError):
        main()
    assert path.read_text() == "preserve"
