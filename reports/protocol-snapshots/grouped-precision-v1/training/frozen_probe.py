"""A fixed frozen-Qwen readout experiment with a training-only lexical control."""

import argparse
import json
import math
import sys
import warnings
from collections import Counter
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sentinel.modeling.clones import normalized_tokens
from sentinel.modeling.properties import PROPERTIES
from sentinel.modeling.property_scoring import (
    property_baselines,
    score_properties,
    validation_gate,
)
from training.binary_mlx import (
    encode_row,
    probability,
    read_development,
    source_and_target,
    wilson_interval,
    write_json,
)
from training.diagnose_binary import inspect, ranking
from training.local_model import file_hash, status

PLAN = {
    "name": "frozen-probe-v1", "seed": 419, "max_tokens": 1024, "hidden_size": 1536,
    "feature": "Unadapted Qwen final prompt-token hidden state, L2 row-normalized",
    "heads": "One binary logistic regression per property; no cross-property head selection",
    "solver": "liblinear", "penalty": "l2", "C": 1.0, "tol": 0.0001, "max_iter": 2000,
    "fit_intercept": True, "class_weight": None, "threshold": 0.5,
    "scikit_learn": "1.7.2", "lexical_max_features": 4096,
    "lexical_control": "Per-property normalized-token unigram TF-IDF fitted on selected training sources only",
    "hyperparameter_search": False, "calibration": False, "base_weights_updated": False,
    "scope": "Exploratory development on historical unreviewed labels, not independent validation or deployment approval. "
             "No threshold sweep, model selection between controls, label changes or reserved test access.",
}
CODE = ("training/frozen_probe.py", "training/binary_mlx.py", "training/diagnose_binary.py",
        "training/local_model.py", "sentinel/modeling/clones.py", "sentinel/modeling/properties.py",
        "sentinel/modeling/property_scoring.py", "sentinel/modeling/data.py")


def selected_rows(splits: dict, selection: dict) -> dict:
    result = {}
    for split in ("train", "valid"):
        index = {row["id"]: row for row in splits[split]}
        ids = selection[f"{split}_ids"]
        if not ids or len(ids) != len(set(ids)) or not set(ids) <= index.keys():
            raise ValueError("Frozen selection identities differ")
        result[split] = [index[key] for key in ids]
        counts = Counter(f"{row['swc']}:{str(source_and_target(row)[1]['vulnerable']).lower()}" for row in result[split])
        saved = selection[split]
        if len(ids) != saved["selected"] or len(ids) != saved["unique"] or dict(counts) != saved["per_bucket"]:
            raise ValueError("Frozen selection counts differ")
    if {r["id"] for r in result["train"]} & {r["id"] for r in result["valid"]}:
        raise ValueError("Training and validation selections overlap")
    return result


def prepare(run: Path, dataset: Path, model: Path, output: Path) -> dict:
    output = output.resolve()
    if output.exists():
        raise FileExistsError("Use a new output directory; prior experiments are immutable")
    if any(output.is_relative_to(path.resolve()) for path in (run, dataset, model)):
        raise ValueError("Experiment output must be outside frozen inputs")
    diagnostic, valid, _ = inspect(run, dataset)
    splits, pins = read_development(dataset)
    if pins != diagnostic["training_input_pins"]:
        raise ValueError("Dataset changed during preparation")
    selection = json.loads((run / "data-selection.json").read_text())
    rows = selected_rows(splits, selection)
    if set(valid) != {row["id"] for row in rows["valid"]}:
        raise ValueError("Validation cohort differs from original diagnostic")
    readiness = status(model)
    original = json.loads((run / "run.json").read_text())
    if (not readiness["ready_for_local_inference"] or readiness["base_model"] != original["base_model"]
            or file_hash(model / "sentinel-weights.json") != original["base_receipt_sha256"]):
        raise ValueError("Verified original base model required")
    protocol = {"plan": PLAN, "created_at": datetime.now(UTC).isoformat(),
                "source_run": str(run.resolve()), "dataset": str(dataset.resolve()), "model": str(model.resolve()),
                "base_model": readiness["base_model"], "base_receipt_sha256": original["base_receipt_sha256"],
                "input_pins": pins, "source_run_pins": diagnostic["input_pins"],
                "implementation_sha256": {name: file_hash(ROOT / name) for name in CODE},
                "selection": selection, "reserved_test_accessed": False, "historical_labels_reviewed": False}
    output.mkdir(parents=True)
    write_json(output / "protocol.json", protocol)
    return {"protocol": str(output / "protocol.json"), "training_cases": len(rows["train"]),
            "validation_cases": len(rows["valid"]), "status": "fixed_before_new_scoring"}


def load_protocol(output: Path) -> tuple[dict, dict]:
    protocol = json.loads((output / "protocol.json").read_text())
    if protocol.get("plan") != PLAN or set(protocol.get("implementation_sha256", {})) != set(CODE):
        raise ValueError("Fixed probe protocol differs")
    for name, pin in protocol["implementation_sha256"].items():
        if file_hash(ROOT / name) != pin:
            raise ValueError("Implementation changed after protocol preparation")
    for name, pin in protocol["source_run_pins"].items():
        if file_hash(Path(name)) != pin:
            raise ValueError("Source experiment evidence changed")
    splits, pins = read_development(Path(protocol["dataset"]))
    if pins != protocol["input_pins"]:
        raise ValueError("Prepared dataset pins changed")
    rows = selected_rows(splits, protocol["selection"])
    return protocol, rows


def extract(output: Path) -> dict:
    if any((output / name).exists() for name in ("features.npz", "features.json")):
        raise FileExistsError("Feature artifacts already exist; do not overwrite")
    protocol, rows = load_protocol(output)
    model_path = Path(protocol["model"])
    readiness = status(model_path)
    if (not readiness["ready_for_local_inference"] or readiness["base_model"] != protocol["base_model"]
            or file_hash(model_path / "sentinel-weights.json") != protocol["base_receipt_sha256"]):
        raise ValueError("Frozen base model integrity differs")
    import mlx.core as mx
    import numpy as np
    from mlx_lm import load
    from mlx_lm.utils import get_total_parameters

    model, tokenizer = load(str(model_path))
    model.freeze()
    model.eval()
    parameter_count = get_total_parameters(model)
    if parameter_count != 1543714304:
        raise ValueError("Expected the pinned 1.5B base model")
    labels = [tokenizer.encode(label, add_special_tokens=False) for label in ("false", "true")]
    if any(len(ids) != 1 for ids in labels) or labels[0] == labels[1]:
        raise ValueError("Original single-token label mapping required")
    label_ids = mx.array([ids[0] for ids in labels])
    original = json.loads((Path(protocol["source_run"]) / "base-validation.json").read_text())
    expected = {row["id"]: row["label_logits_false_true"] for row in original["predictions"]}
    matrices, lengths = {}, {}
    started = datetime.now(UTC).isoformat()
    for split in ("train", "valid"):
        vectors, lengths[split] = [], []
        for index, row in enumerate(rows[split], start=1):
            tokens = encode_row(row, tokenizer)["tokens"]
            if not tokens or len(tokens) + 1 > PLAN["max_tokens"]:
                raise ValueError("A frozen case exceeds the budget; never truncate or drop it")
            hidden = model.model(mx.array([tokens]))[:, -1:, :]
            mx.eval(hidden)
            vector = np.asarray(hidden[0, 0].astype(mx.float32)).copy()
            if vector.shape != (PLAN["hidden_size"],) or not np.isfinite(vector).all():
                raise ValueError("Invalid frozen representation")
            if split == "valid":
                logits = model.model.embed_tokens.as_linear(hidden)[:, 0, label_ids].astype(mx.float32)
                mx.eval(logits)
                if not np.allclose(np.asarray(logits[0]), expected[row["id"]], atol=0.05, rtol=0.01):
                    raise ValueError("Base logits do not reproduce the original input/model")
            vectors.append(vector)
            lengths[split].append(len(tokens))
            if index % 16 == 0 or index == len(rows[split]):
                print(f"Frozen features {split}: {index}/{len(rows[split])}", flush=True)
            mx.clear_cache()
        matrices[split] = np.stack(vectors).astype(np.float32)
    with (output / "features.npz").open("xb") as handle:
        np.savez_compressed(handle, **matrices)
    receipt = {"protocol_sha256": file_hash(output / "protocol.json"),
               "features_sha256": file_hash(output / "features.npz"),
               "ids": {split: [row["id"] for row in items] for split, items in rows.items()},
               "token_lengths": lengths, "shapes": {name: list(matrix.shape) for name, matrix in matrices.items()},
               "base_parameter_count": parameter_count, "base_weights_updated": False,
               "validation_logit_reproduction": {"passed": True, "atol": 0.05, "rtol": 0.01},
               "packages": {name: version(name) for name in ("mlx", "mlx-lm", "numpy", "transformers")},
               "peak_mlx_memory_bytes": mx.get_peak_memory(), "started_at": started,
               "finished_at": datetime.now(UTC).isoformat(), "reserved_test_accessed": False}
    write_json(output / "features.json", receipt)
    return receipt


def validate_receipt(output: Path, rows: dict, receipt: dict) -> None:
    if (receipt.get("protocol_sha256") != file_hash(output / "protocol.json")
            or receipt.get("features_sha256") != file_hash(output / "features.npz")
            or receipt.get("ids") != {split: [row["id"] for row in items] for split, items in rows.items()}
            or receipt.get("shapes") != {split: [len(items), PLAN["hidden_size"]] for split, items in rows.items()}
            or receipt.get("base_parameter_count") != 1543714304 or receipt.get("base_weights_updated") is not False
            or receipt.get("reserved_test_accessed") is not False
            or receipt.get("validation_logit_reproduction") != {"passed": True, "atol": 0.05, "rtol": 0.01}):
        raise ValueError("Features must match the exact frozen cohort, protocol and base model")
    for split, items in rows.items():
        lengths = receipt.get("token_lengths", {}).get(split, [])
        if len(lengths) != len(items) or any(type(n) is not int or not 0 < n < PLAN["max_tokens"] for n in lengths):
            raise ValueError("Feature token-budget evidence differs")


def evaluate(rows: list[dict], margins: dict[str, float]) -> dict:
    if len(rows) != len({row["id"] for row in rows}) or {row["id"] for row in rows} != margins.keys():
        raise ValueError("Every assessment requires exactly one classifier margin")
    predictions = []
    for row in rows:
        _, target = source_and_target(row)
        margin = margins[row["id"]]
        if type(margin) not in (int, float) or not math.isfinite(margin):
            raise ValueError("Finite classifier margins required")
        score = probability([0.0, margin])
        predictions.append({"id": row["id"], "expected": json.dumps(target),
                            "prediction": json.dumps({"swc": target["swc"], "vulnerable": score > PLAN["threshold"]}),
                            "classifier_margin": margin, "classifier_score": score})
    scores = score_properties(predictions)
    ordering = ranking([{"expected": row["expected"], "conditional_true_score": row["classifier_score"]}
                        for row in predictions])
    return {"scores": scores, "precision_interval": wilson_interval(scores["tp"], scores["tp"] + scores["fp"]),
            "pair_ordering": ordering, "predictions": predictions,
            "scope": "Classifier scores are not calibrated vulnerability probabilities or Boolean-token logits."}


def score(output: Path) -> dict:
    if any((output / name).exists() for name in ("classifiers.json", "comparison.json")):
        raise FileExistsError("Classifier results already exist; preserve earlier attempts")
    _protocol, rows = load_protocol(output)
    receipt = json.loads((output / "features.json").read_text())
    validate_receipt(output, rows, receipt)
    if version("scikit-learn") != PLAN["scikit_learn"]:
        raise ValueError("Install the protocol's pinned scikit-learn version")
    import numpy as np
    from sklearn.exceptions import ConvergenceWarning
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import normalize

    with np.load(output / "features.npz", allow_pickle=False) as archive:
        if set(archive.files) != {"train", "valid"}:
            raise ValueError("Unexpected feature archive members")
        matrices = {split: archive[split] for split in rows}
    for split, matrix in matrices.items():
        if (matrix.shape != (len(rows[split]), PLAN["hidden_size"]) or matrix.dtype != np.float32
                or not np.isfinite(matrix).all() or np.any(np.linalg.norm(matrix, axis=1) == 0)):
            raise ValueError("Invalid frozen feature matrix")
    parameters, results = {}, {}
    for method in ("frozen_qwen", "lexical_control"):
        margins = {split: {} for split in rows}
        parameters[method] = {}
        for swc in PROPERTIES:
            indices = {split: [i for i, row in enumerate(items) if row["swc"] == swc] for split, items in rows.items()}
            targets = [int(source_and_target(rows["train"][i])[1]["vulnerable"]) for i in indices["train"]]
            if set(targets) != {0, 1} or not indices["valid"]:
                raise ValueError("Every property requires both training labels and retained validation cases")
            preprocessing = {"normalization": "L2 per row, no validation-fitted statistics"}
            if method == "frozen_qwen":
                inputs = {split: normalize(matrix[indices[split]], norm="l2") for split, matrix in matrices.items()}
            else:
                texts = {split: [source_and_target(rows[split][i])[0] for i in indices[split]] for split in rows}
                vectorizer = TfidfVectorizer(analyzer=normalized_tokens, max_features=PLAN["lexical_max_features"])
                inputs = {"train": vectorizer.fit_transform(texts["train"]), "valid": vectorizer.transform(texts["valid"])}
                preprocessing = {"vocabulary": {token: int(index) for token, index in vectorizer.vocabulary_.items()},
                                 "idf": vectorizer.idf_.tolist(),
                                 "normalization": "L2 TF-IDF; fitted exclusively on training sources"}
            classifier = LogisticRegression(C=PLAN["C"], solver=PLAN["solver"], penalty=PLAN["penalty"],
                tol=PLAN["tol"], max_iter=PLAN["max_iter"], random_state=PLAN["seed"],
                fit_intercept=PLAN["fit_intercept"], class_weight=PLAN["class_weight"])
            with warnings.catch_warnings():
                warnings.simplefilter("error", ConvergenceWarning)
                classifier.fit(inputs["train"], targets)
            if classifier.classes_.tolist() != [0, 1]:
                raise ValueError("Unexpected classifier class mapping")
            for split in rows:
                values = classifier.decision_function(inputs[split]).tolist()
                margins[split].update({rows[split][i]["id"]: value for i, value in zip(indices[split], values, strict=True)})
            parameters[method][swc] = {"classes": [0, 1], "coefficients": classifier.coef_.tolist(),
                                       "intercept": classifier.intercept_.tolist(), "iterations": classifier.n_iter_.tolist(),
                                       "preprocessing": preprocessing}
        results[method] = {split: evaluate(items, margins[split]) for split, items in rows.items()}
    baselines = property_baselines(rows["train"], rows["valid"])
    comparison = {"plan": PLAN, "results": results, "baselines": baselines,
                  "development_gates": {name: validation_gate(value["valid"]["scores"], baselines) for name, value in results.items()},
                  "protocol_sha256": file_hash(output / "protocol.json"), "features_receipt_sha256": file_hash(output / "features.json"),
                  "packages": {name: version(name) for name in ("numpy", "scipy", "scikit-learn")},
                  "training_cases": len(rows["train"]), "validation_cases": len(rows["valid"]),
                  "base_parameter_count": receipt["base_parameter_count"], "base_weights_updated": False,
                  "historical_labels_reviewed": False, "reserved_test_accessed": False,
                  "independent_99_percent_claim_supported": False,
                  "scope": "Fixed exploratory readout comparison; retain both controls, not a model-selection exercise. "
                           "All 54 intended development cases retained. Human label/context review remains pending."}
    write_json(output / "classifiers.json", parameters)
    comparison["classifiers_sha256"] = file_hash(output / "classifiers.json")
    write_json(output / "comparison.json", comparison)
    return {"results": {name: value["valid"]["scores"] for name, value in results.items()},
            "development_gates": comparison["development_gates"], "independent_99_percent_claim_supported": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "extract", "score"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run", type=Path, default=ROOT / "training/runs/mac-binary-v1")
    parser.add_argument("--dataset", type=Path, default=ROOT / "datasets/model-properties")
    parser.add_argument("--model", type=Path, default=ROOT / "models/qwen-coder-1.5b-4bit")
    parser.add_argument("--experimental", action="store_true")
    args = parser.parse_args()
    if args.action != "prepare" and not args.experimental:
        raise SystemExit("Feature extraction and probe fitting require --experimental; the model is unqualified")
    result = prepare(args.run, args.dataset, args.model, args.output) if args.action == "prepare" else (
        extract(args.output) if args.action == "extract" else score(args.output))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
