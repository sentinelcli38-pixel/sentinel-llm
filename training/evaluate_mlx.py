"""Generate predictions with the base model or its Sentinel adapter and score them."""

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.modeling.data import read_jsonl
from sentinel.modeling.property_scoring import (
    property_baselines,
    score_properties,
    validation_gate,
)
from sentinel.modeling.scoring import score_predictions


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="models/qwen-coder-1.5b-4bit")
    parser.add_argument("--adapter", type=Path)
    parser.add_argument("--data", type=Path, default=Path("datasets/model-training-fit/test.jsonl"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-tokens", type=int, default=256)
    parser.add_argument("--task", choices=["findings", "swc_property"], default="findings")
    parser.add_argument("--validation-gate", action="store_true")
    args = parser.parse_args()
    if args.max_tokens < 1:
        raise SystemExit("--max-tokens must be positive")
    if args.validation_gate and (args.task != "swc_property" or args.data.name != "valid.jsonl"):
        raise SystemExit("The development gate is only for the property validation split, never the test split")
    if args.output.exists():
        raise SystemExit("Output already exists; choose a new path to preserve earlier predictions")
    import mlx.core as mx
    from mlx_lm import generate, load
    from mlx_lm.sample_utils import make_sampler

    mx.random.seed(42)
    model, tokenizer = load(args.model, adapter_path=str(args.adapter) if args.adapter else None)
    rows = read_jsonl(args.data)
    if not rows or any(row.get("task", "findings") != args.task for row in rows):
        raise SystemExit("Empty dataset or dataset task differs from --task")
    records = []
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w") as handle:
        for row in rows:
            prompt = tokenizer.apply_chat_template(row["messages"][:-1], tokenize=False, add_generation_prompt=True)
            prediction = generate(model, tokenizer, prompt=prompt, max_tokens=args.max_tokens, sampler=make_sampler(temp=0.0), verbose=False)
            record = {"id": row["id"], "expected": row["messages"][-1]["content"], "prediction": prediction}
            records.append(record)
            handle.write(json.dumps(record) + "\n")
            handle.flush()
            print(f"Predicted {row['id']} ({len(records)} cases)", flush=True)
    summary = {
        "task": args.task,
        "model": args.model, "adapter": str(args.adapter) if args.adapter else None,
        "base_model": json.loads((Path(args.model) / "sentinel-base.json").read_text()),
        "dataset_path": str(args.data),
        "dataset_sha256": hashlib.sha256(args.data.read_bytes()).hexdigest(),
        "max_tokens": args.max_tokens, "temperature": 0.0,
        "created_at": datetime.now(UTC).isoformat(),
        "scores": score_properties(records) if args.task == "swc_property" else score_predictions(records),
    }
    if args.adapter:
        summary["adapter_sha256"] = hashlib.sha256((args.adapter / "adapters.safetensors").read_bytes()).hexdigest()
        selection = args.adapter / "selection.json"
        if selection.is_file():
            summary["checkpoint_selection"] = json.loads(selection.read_text())
    if args.task == "swc_property":
        train_path = args.data.parent / "train.jsonl"
        summary["training_sha256"] = hashlib.sha256(train_path.read_bytes()).hexdigest()
        summary["baselines"] = property_baselines(read_jsonl(train_path), rows)
        if args.validation_gate:
            summary["validation_gate"] = validation_gate(summary["scores"], summary["baselines"])
    args.output.with_suffix(".summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary["scores"], indent=2))


if __name__ == "__main__":
    main()
