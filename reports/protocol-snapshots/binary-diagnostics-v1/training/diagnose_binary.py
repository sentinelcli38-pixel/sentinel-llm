"""Audit saved binary-model evidence and measure source ablations, not accuracy gains."""

import argparse
import hashlib
import json
import math
import random
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sentinel.modeling.properties import PROPERTIES
from sentinel.modeling.property_scoring import parse_property, score_properties
from training.binary_mlx import (
    PLAN,
    SYSTEM,
    binary_nll,
    probability,
    read_development,
    source_and_target,
    write_json,
)
from training.local_model import file_hash, status

ABLATION_PLAN = {"seed": 313, "maximum_per_label_per_property": 2,
                 "variants": ["full", "without_source", "property_only"],
                 "weights_updated": False, "threshold_selected": False,
                 "scope": "Missing-source variants have unknown ground truth and are never scored as accuracy."}


def distribution(values: list[float]) -> dict:
    if not values or not all(math.isfinite(value) for value in values):
        raise ValueError("Nonempty finite scores required")
    return {"count": len(values), "minimum": min(values), "maximum": max(values),
            "mean": statistics.mean(values), "standard_deviation": statistics.pstdev(values),
            "distinct": len(set(values))}


def ranking(rows: list[dict]) -> dict:
    groups = {truth: [row["conditional_true_score"] for row in rows
                     if parse_property(row["expected"])["vulnerable"] is truth] for truth in (False, True)}
    positive, negative = groups[True], groups[False]
    pairs = len(positive) * len(negative)
    wins = sum(a > b for a in positive for b in negative)
    ties = sum(a == b for a in positive for b in negative)
    return {"positive_cases": len(positive), "negative_cases": len(negative), "pairs": pairs,
            "positive_higher_pairs": wins, "tied_pairs": ties,
            "pair_ordering_score": (wins + 0.5 * ties) / pairs if pairs else None,
            "positive_scores": distribution(positive) if positive else None,
            "negative_scores": distribution(negative) if negative else None,
            "scope": "Descriptive positive/negative pair ordering (ROC AUC), ties count half. "
                     "Not accuracy, precision, calibration or independent generalization."}


def verify_predictions(document: dict, ids: list[str], expected: dict) -> list[dict]:
    rows = document.get("predictions", [])
    if len({row["id"] for row in rows}) != len(rows) or {row["id"] for row in rows} != set(ids) or len(rows) != len(ids):
        raise ValueError("Predictions must retain every selected validation ID exactly once")
    for row in rows:
        target = parse_property(row["expected"])
        actual = parse_property(row["prediction"], target["swc"])
        if target != expected[row["id"]]:
            raise ValueError("Prediction labels differ from frozen validation data")
        score = probability(row["label_logits_false_true"])
        if (type(row.get("conditional_true_score")) not in (float, int)
                or not math.isfinite(row["conditional_true_score"])
                or abs(score - row["conditional_true_score"]) > 1e-12
                or actual["vulnerable"] != (score > PLAN["threshold"])):
            raise ValueError("Saved score or fixed-threshold decision differs from logits")
    if score_properties(rows) != document.get("scores"):
        raise ValueError("Saved metrics differ from complete predictions")
    return rows


def inspect(run: Path, dataset: Path) -> tuple[dict, dict, dict]:
    record = json.loads((run / "run.json").read_text())
    selection = json.loads((run / "data-selection.json").read_text())
    checkpoint = json.loads((run / "selected-adapter/selection.json").read_text())
    comparison = json.loads((run / "comparison.json").read_text())
    if record.get("status") != "completed" or record.get("plan") != PLAN:
        raise ValueError("Expected a completed, unchanged binary-v1 protocol")
    if file_hash(ROOT / "training/binary_mlx.py") != record.get("implementation_sha256"):
        raise ValueError("Training implementation differs; use its preserved snapshot")
    candidates = checkpoint.get("candidates", [])
    if not isinstance(candidates, list) or not candidates or any(
        type(item.get("step")) is not int
        or type(item.get("boolean_validation_loss")) not in (float, int)
        or not math.isfinite(item["boolean_validation_loss"]) for item in candidates
    ):
        raise ValueError("Checkpoint steps and losses must be finite recorded values")
    required_steps = list(range(PLAN["evaluate_every"], PLAN["steps"] + 1, PLAN["evaluate_every"]))
    if sorted(item["step"] for item in candidates) != required_steps:
        raise ValueError("Every planned checkpoint must be retained exactly once")
    best = min(candidates, key=lambda item: (item["boolean_validation_loss"], item["step"]))
    for field in ("step", "checkpoint_sha256", "boolean_validation_loss"):
        if checkpoint.get(field) != best[field] or record["checkpoint_selection"].get(field) != best[field]:
            raise ValueError("Checkpoint selection differs from the recorded minimum-loss rule")
    if (checkpoint["checkpoint_sha256"] != file_hash(run / "selected-adapter/adapters.safetensors")
            or checkpoint["step"] != comparison["selected_step"] or record["checkpoint_selection"]["step"] != checkpoint["step"]):
        raise ValueError("Selected checkpoint evidence differs")
    splits, pins = read_development(dataset)
    if pins != record["input_pins"] or selection.get("input_pins") != pins:
        raise ValueError("Frozen input pins differ from the recorded training run")
    valid_by_id = {row["id"]: row for row in splits["valid"]}
    ids = selection["valid_ids"]
    if len(ids) != len(set(ids)) or not set(ids) <= valid_by_id.keys() or len(ids) != selection["valid"]["selected"]:
        raise ValueError("Selected validation identities differ")
    expected = {key: source_and_target(valid_by_id[key])[1] for key in ids}
    base_path = run / "base-validation.json"
    adapted_path = run / f"validation-step-{checkpoint['step']}.json"
    base_doc, adapted_doc = (json.loads(path.read_text()) for path in (base_path, adapted_path))
    base, adapted = (verify_predictions(doc, ids, expected) for doc in (base_doc, adapted_doc))
    if comparison.get("base") != base_doc["scores"] or comparison.get("adapted") != adapted_doc["scores"]:
        raise ValueError("Comparison metrics differ from original prediction reports")
    adapted_by_id = {row["id"]: row for row in adapted}
    shifts = []
    for before in base:
        after = adapted_by_id[before["id"]]
        shifts.append((after["label_logits_false_true"][1] - after["label_logits_false_true"][0])
                      - (before["label_logits_false_true"][1] - before["label_logits_false_true"][0]))
    history = []
    input_paths = [run / "run.json", run / "data-selection.json", run / "comparison.json",
                   run / "selected-adapter/selection.json", run / "selected-adapter/adapter_config.json", base_path, adapted_path]
    for candidate in checkpoint["candidates"]:
        weights = run / "adapter" / f"{candidate['step']:07d}_adapters.safetensors"
        if file_hash(weights) != candidate["checkpoint_sha256"]:
            raise ValueError("A retained checkpoint differs from its recorded hash")
        path = run / f"validation-step-{candidate['step']}.json"
        document = json.loads(path.read_text())
        rows = verify_predictions(document, ids, expected)
        labels = [{"vulnerable": parse_property(row["expected"])["vulnerable"]} for row in rows]
        nll = binary_nll(labels, [row["label_logits_false_true"] for row in rows])
        if abs(nll - candidate["boolean_validation_loss"]) > 1e-12:
            raise ValueError("Checkpoint validation loss differs from saved predictions")
        history.append({"step": candidate["step"], "boolean_loss": nll,
                        "ranking": ranking(rows), "scores": {key: document["scores"][key]
                                    for key in ("tp", "fp", "tn", "fn", "precision", "recall", "specificity")}})
        input_paths.append(path)
    train_by_id = {row["id"]: row for row in splits["train"]}
    seen = record["trained_row_ids"]
    if (len(seen) != record["examples_seen"] or len(set(seen)) != record["unique_examples_seen"]
            or not set(seen) <= set(selection["train_ids"]) or not set(seen) <= train_by_id.keys()):
        raise ValueError("Training exposure evidence differs")
    labels_seen = Counter(str(source_and_target(train_by_id[key])[1]["vulnerable"]).lower() for key in seen)
    result = {"run": str(run.resolve()), "role": "development_diagnostics_only", "validation_cases": len(ids),
              "base": ranking(base), "adapted": ranking(adapted), "logit_margin_shift": distribution(shifts),
              "per_property": {swc: {"base": ranking([row for row in base if expected[row["id"]]["swc"] == swc]),
                                     "adapted": ranking([row for row in adapted if expected[row["id"]]["swc"] == swc])}
                               for swc in PROPERTIES},
              "checkpoints": history, "training_exposure": dict(labels_seen),
              "input_pins": {str(path.resolve()): file_hash(path) for path in sorted(set(input_paths))},
              "training_input_pins": pins, "selected_adapter_sha256": checkpoint["checkpoint_sha256"],
              "diagnostic_code_sha256": file_hash(Path(__file__)), "reserved_test_accessed": False,
              "threshold_changed": False, "model_updated": False, "claim_99_percent_supported": False,
              "scope": "Saved-score diagnostic; does not identify the cause of failure, validate historical labels, "
                       "choose a new threshold or establish independent model accuracy."}
    return result, {key: valid_by_id[key] for key in ids}, {"base": {r["id"]: r for r in base}, "adapted": adapted_by_id}


def sample_cases(rows: dict) -> list[dict]:
    buckets = defaultdict(list)
    for row in rows.values():
        target = source_and_target(row)[1]
        buckets[(target["swc"], target["vulnerable"])].append(row)
    rng = random.Random(ABLATION_PLAN["seed"])
    sampled = []
    for key in sorted(buckets):
        candidates = sorted(buckets[key], key=lambda row: row["id"])
        rng.shuffle(candidates)
        sampled.extend(candidates[:ABLATION_PLAN["maximum_per_label_per_property"]])
    return sampled


def prompt_messages(row: dict, variant: str) -> list[dict]:
    source, target = source_and_target(row)
    if variant not in ABLATION_PLAN["variants"]:
        raise ValueError("Unsupported ablation variant")
    header = f"Assess SWC-{target['swc']} ({PROPERTIES[target['swc']]}) in contract {row['contract']}.\n\n"
    if variant == "full":
        content = header + source
    elif variant == "without_source":
        content = header + "[Source withheld for diagnostic ablation.]"
    else:
        content = f"Assess SWC-{target['swc']} ({PROPERTIES[target['swc']]}) in a Solidity contract.\n\n[Source and target name withheld for diagnostic ablation.]"
    return [{"role": "system", "content": SYSTEM}, {"role": "user", "content": content}]


def ablate(run: Path, dataset: Path, model_path: Path) -> dict:
    diagnostic, rows, saved = inspect(run, dataset)
    readiness = status(model_path)
    record = json.loads((run / "run.json").read_text())
    if (not readiness["ready_for_local_inference"] or readiness["base_model"] != record["base_model"]
            or file_hash(model_path / "sentinel-weights.json") != record["base_receipt_sha256"]):
        raise ValueError("Pinned base model differs from the training run")
    import mlx.core as mx
    from mlx_lm import load
    from mlx_lm.utils import load_adapters

    current, tokenizer = load(str(model_path))
    label_tokens = [tokenizer.encode(text, add_special_tokens=False) for text in ("false", "true")]
    if any(len(ids) != 1 for ids in label_tokens):
        raise ValueError("Boolean labels must be single tokens")
    ids = mx.array([tokens[0] for tokens in label_tokens])
    selected, details = sample_cases(rows), []
    for model_name in ("base", "adapted"):
        if model_name == "adapted":
            current = load_adapters(current, str(run / "selected-adapter"))
        current.eval()
        cached = {}
        for index, row in enumerate(selected, start=1):
            scores = {}
            for variant in ABLATION_PLAN["variants"]:
                prompt = tokenizer.apply_chat_template(prompt_messages(row, variant), tokenize=False, add_generation_prompt=True)
                tokens = tokenizer.encode(prompt, add_special_tokens=False)
                if not tokens or len(tokens) + 1 > PLAN["max_tokens"]:
                    raise ValueError("Ablation input exceeds the frozen token budget; never truncate")
                key = tuple(tokens)
                if key not in cached:
                    hidden = current.model(mx.array([tokens]))[:, -1:, :]
                    values = current.model.embed_tokens.as_linear(hidden)[:, 0, ids].astype(mx.float32)
                    mx.eval(values)
                    cached[key] = values[0].tolist()
                    mx.clear_cache()
                scores[variant] = {"logits_false_true": cached[key], "conditional_true_score": probability(cached[key]),
                                   "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest()}
            expected = saved[model_name][row["id"]]["label_logits_false_true"]
            actual = scores["full"]["logits_false_true"]
            if any(abs(a - b) > 0.05 + 0.01 * abs(b) for a, b in zip(actual, expected, strict=True)):
                raise ValueError("Full-input logits do not reproduce saved evidence")
            details.append({"id": row["id"], "swc": row["swc"], "model": model_name, "variants": scores,
                            "ablation_ground_truth": "unknown", "used_for_accuracy": False})
            print(f"{model_name} source ablation: {index}/{len(selected)}", flush=True)
    summary = {}
    for model_name in ("base", "adapted"):
        model_rows = [item for item in details if item["model"] == model_name]
        summary[model_name] = {variant: {"absolute_score_change": distribution([
            abs(item["variants"]["full"]["conditional_true_score"] - item["variants"][variant]["conditional_true_score"])
            for item in model_rows]), "decisions_changed": sum(
                (item["variants"]["full"]["conditional_true_score"] > 0.5)
                != (item["variants"][variant]["conditional_true_score"] > 0.5) for item in model_rows)}
                              for variant in ("without_source", "property_only")}
    return {"plan": ABLATION_PLAN, "sampled_case_ids": [row["id"] for row in selected], "summary": summary,
            "cases": details, "source_diagnostic": diagnostic, "reserved_test_accessed": False,
            "scope": "Input sensitivity only. Removed-source prompts are unassessable, not negative controls. "
                     "Score movement or a decision flip does not prove semantic reasoning or an accurate detector."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["offline", "ablate"])
    parser.add_argument("--run", type=Path, default=Path("training/runs/mac-binary-v1"))
    parser.add_argument("--dataset", type=Path, default=Path("datasets/model-properties"))
    parser.add_argument("--model", type=Path, default=Path("models/qwen-coder-1.5b-4bit"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--experimental", action="store_true")
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("Preserve existing diagnostics; choose a new output path")
    if args.action == "ablate" and not args.experimental:
        raise SystemExit("Ablation requires --experimental; these are unqualified research predictions")
    result = ablate(args.run, args.dataset, args.model) if args.action == "ablate" else inspect(args.run, args.dataset)[0]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json(args.output, result)
    print(f"Diagnostic report: {args.output}; 99% claim supported: False")


if __name__ == "__main__":
    main()
