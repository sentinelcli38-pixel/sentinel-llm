"""Compare saved model predictions and a training-only majority-label baseline."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.modeling.data import read_jsonl
from sentinel.modeling.property_scoring import (
    property_baselines,
    score_properties,
    validation_gate,
)
from sentinel.modeling.scoring import majority_category_baseline, score_predictions


def compact_results(value):
    if isinstance(value, dict):
        return {key: compact_results(item) for key, item in value.items() if key not in {"cases_detail", "per_swc"}}
    if isinstance(value, list):
        return [compact_results(item) for item in value]
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, default=Path("training/runs/base-predictions.jsonl"))
    parser.add_argument("--adapted", type=Path, default=Path("training/runs/adapter-predictions.jsonl"))
    parser.add_argument("--data", type=Path, default=Path("datasets/model-training-fit"))
    parser.add_argument("--output", type=Path, default=Path("training/runs/pilot-comparison.json"))
    parser.add_argument("--task", choices=["findings", "swc_property"], default="findings")
    parser.add_argument("--split", choices=["valid", "test"], default="test")
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("Comparison already exists; choose a new output path")
    evaluation_path = args.data / f"{args.split}.jsonl"
    digest = hashlib.sha256(evaluation_path.read_bytes()).hexdigest()
    test = read_jsonl(evaluation_path)
    expected = [(row["id"], row["messages"][-1]["content"]) for row in test]
    results = {}
    metadata = {}
    for name, path in (("base", args.base), ("adapter", args.adapted)):
        rows = read_jsonl(path)
        if [(row["id"], row["expected"]) for row in rows] != expected:
            raise SystemExit(f"{name} predictions do not match the frozen evaluation cases")
        results[name] = score_properties(rows) if args.task == "swc_property" else score_predictions(rows)
        if args.task == "swc_property":
            metadata[name] = json.loads(path.with_suffix(".summary.json").read_text())
            if metadata[name]["dataset_sha256"] != digest or metadata[name]["task"] != args.task:
                raise SystemExit("Evaluation metadata differs from the selected data")
    training = read_jsonl(args.data / "train.jsonl")
    if args.task == "swc_property":
        for key in ("base_model", "max_tokens", "temperature", "training_sha256"):
            if metadata["base"][key] != metadata["adapter"][key]:
                raise SystemExit(f"Model comparison differs in {key}")
        if metadata["base"]["training_sha256"] != hashlib.sha256((args.data / "train.jsonl").read_bytes()).hexdigest():
            raise SystemExit("Training data differs from the evaluated experiment")
        results["baselines"] = property_baselines(training, test)
        results["checkpoint_selection"] = metadata["adapter"].get("checkpoint_selection")
        if args.split == "valid":
            results["validation_gate"] = validation_gate(results["adapter"], results["baselines"])
    else:
        results["majority_baseline"] = majority_category_baseline(training, test)
    results["evaluation_sha256"] = digest
    results["task"] = args.task
    results["split"] = args.split
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(compact_results(results), indent=2))


if __name__ == "__main__":
    main()
