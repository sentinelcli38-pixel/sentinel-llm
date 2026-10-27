"""Assess one local Solidity source with the base model or a trained adapter."""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.modeling.data import prompt_messages, strip_comments
from sentinel.modeling.properties import PROPERTIES, property_messages
from sentinel.modeling.property_scoring import parse_property
from sentinel.modeling.scoring import parse_findings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--model", default="models/qwen-coder-1.5b-4bit")
    parser.add_argument("--adapter", type=Path)
    parser.add_argument("--experimental", action="store_true", help="Explicitly opt into research-only predictions from unqualified models")
    parser.add_argument("--max-input-tokens", type=int, default=1024)
    parser.add_argument("--task", choices=["findings", "swc_property"], default="findings")
    parser.add_argument("--swc", choices=list(PROPERTIES))
    parser.add_argument("--contract")
    args = parser.parse_args()
    if not args.experimental:
        raise SystemExit("Local model inference is research-only: no Sentinel model has passed qualification. Use --experimental to inspect untrusted predictions; never use them as release decisions.")
    if args.task == "swc_property" and (not args.swc or not args.contract):
        raise SystemExit("Property inference requires --swc and --contract")
    if args.adapter:
        run_path = args.adapter.parent / "run.json"
        if run_path.is_file():
            record = json.loads(run_path.read_text())
            task = "swc_property" if record["config"].get("balance_per_bucket") else "findings"
            if task != args.task:
                raise SystemExit("Adapter task differs from the requested inference task")
    import mlx.core as mx
    from mlx_lm import generate, load
    from mlx_lm.sample_utils import make_sampler

    source = strip_comments(args.source.read_text(encoding="utf-8"))
    model, tokenizer = load(args.model, adapter_path=str(args.adapter) if args.adapter else None)
    messages = property_messages(source, args.swc, args.contract) if args.task == "swc_property" else prompt_messages(source)
    prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    if len(tokenizer.encode(prompt)) > args.max_input_tokens:
        raise SystemExit("Source exceeds the input budget; choose a smaller isolated contract")
    mx.random.seed(42)
    prediction = generate(model, tokenizer, prompt=prompt, max_tokens=256, sampler=make_sampler(temp=0.0), verbose=False)
    try:
        if args.task == "swc_property":
            assessment = parse_property(prediction, args.swc)
        else:
            findings = parse_findings(prediction)
            if any(line > len(source.splitlines()) for finding in findings for line in finding["lines"]):
                raise ValueError("Model reported a location outside the supplied source")
            assessment = {"findings": findings}
    except (ValueError, TypeError) as exc:
        print(json.dumps({"status": "invalid_model_output", "raw_prediction": prediction, "error": str(exc)}, indent=2))
        raise SystemExit(2) from exc
    print(json.dumps({"status": "candidate_only", **assessment, "source": str(args.source), "task": args.task,
                      "adapter": str(args.adapter) if args.adapter else None}, indent=2))


if __name__ == "__main__":
    main()
