"""Scale the fixed lexical control to every train/validation assessment, never test."""

import argparse
import json
import sys
import warnings
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sentinel.modeling.clones import normalized_tokens
from sentinel.modeling.properties import PROPERTIES
from sentinel.modeling.property_scoring import property_baselines, validation_gate
from training.binary_mlx import read_development, source_and_target, write_json
from training.frozen_probe import CODE, PLAN, evaluate, load_protocol
from training.local_model import file_hash

SCALE_PLAN = {
    "name": "lexical-scale-v1", "classifier_settings": {key: PLAN[key] for key in (
        "seed", "solver", "penalty", "C", "tol", "max_iter", "fit_intercept", "class_weight",
        "threshold", "scikit_learn", "lexical_max_features")},
    "training": "All original prepared training assessments, no token filter, resampling or class weighting",
    "evaluation": "All original prepared validation assessments; original 54-case subset reported separately",
    "representation": "Normalized-token unigram TF-IDF only, no LLM or model-weight updates",
    "scope": "Same-corpus historical unreviewed development labels; not independent external evidence. "
             "No validation-driven feature/threshold/hyperparameter search. No reserved test access.",
}
IMPLEMENTATIONS = (*CODE, "training/lexical_scale.py")


def prepare(dataset: Path, probe: Path, output: Path) -> dict:
    output = output.resolve()
    if output.exists():
        raise FileExistsError("Preserve prior runs; choose a new output directory")
    if any(output.is_relative_to(path.resolve()) for path in (dataset, probe)):
        raise ValueError("Output must be outside frozen input directories")
    original, subset = load_protocol(probe)
    rows, pins = read_development(dataset)
    if pins != original["input_pins"]:
        raise ValueError("Dataset differs from the original fixed probe")
    comparison = probe / "comparison.json"
    if json.loads(comparison.read_text()).get("protocol_sha256") != file_hash(probe / "protocol.json"):
        raise ValueError("Completed probe evidence required before scale preparation")
    protocol = {"plan": SCALE_PLAN, "dataset": str(dataset.resolve()), "input_pins": pins,
                "implementation_sha256": {name: file_hash(ROOT / name) for name in IMPLEMENTATIONS},
                "original_probe_pins": {str(path.resolve()): file_hash(path) for path in (comparison, probe / "protocol.json")},
                "split_ids": {split: [r["id"] for r in items] for split, items in rows.items()},
                "original_valid_ids": [r["id"] for r in subset["valid"]],
                "created_at": datetime.now(UTC).isoformat(), "reserved_test_accessed": False}
    output.mkdir(parents=True)
    write_json(output / "protocol.json", protocol)
    return {"training_cases": len(rows["train"]), "validation_cases": len(rows["valid"]),
            "original_subset_cases": len(subset["valid"]), "protocol": str(output / "protocol.json")}


def load(output: Path) -> tuple[dict, dict]:
    protocol = json.loads((output / "protocol.json").read_text())
    if protocol.get("plan") != SCALE_PLAN or set(protocol.get("implementation_sha256", {})) != set(IMPLEMENTATIONS):
        raise ValueError("Scale protocol differs from the fixed procedure")
    for name, pin in protocol["implementation_sha256"].items():
        if file_hash(ROOT / name) != pin:
            raise ValueError("Implementation changed after preparation")
    for name, pin in protocol["original_probe_pins"].items():
        if file_hash(Path(name)) != pin:
            raise ValueError("Original probe evidence changed")
    rows, pins = read_development(Path(protocol["dataset"]))
    if pins != protocol["input_pins"] or protocol["split_ids"] != {split: [r["id"] for r in items] for split, items in rows.items()}:
        raise ValueError("Complete train/validation identities or hashes differ")
    subset = protocol["original_valid_ids"]
    if not subset or len(subset) != len(set(subset)) or not set(subset) <= {r["id"] for r in rows["valid"]}:
        raise ValueError("Invalid original validation subset")
    return protocol, rows


def score(output: Path) -> dict:
    if any((output / name).exists() for name in ("classifiers.json", "comparison.json")):
        raise FileExistsError("Existing classifier artifacts must not be overwritten")
    protocol, rows = load(output)
    if version("scikit-learn") != PLAN["scikit_learn"]:
        raise ValueError("Pinned scikit-learn required")
    from sklearn.exceptions import ConvergenceWarning
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression

    parameters, margins = {}, {}
    for swc in PROPERTIES:
        training = [r for r in rows["train"] if r["swc"] == swc]
        valid = [r for r in rows["valid"] if r["swc"] == swc]
        labels = [int(source_and_target(r)[1]["vulnerable"]) for r in training]
        if set(labels) != {0, 1} or not valid:
            raise ValueError("Every property requires both training labels and validation coverage")
        vectorizer = TfidfVectorizer(analyzer=normalized_tokens, max_features=PLAN["lexical_max_features"])
        features = vectorizer.fit_transform([source_and_target(r)[0] for r in training])
        classifier = LogisticRegression(C=PLAN["C"], solver=PLAN["solver"], penalty=PLAN["penalty"], tol=PLAN["tol"],
            max_iter=PLAN["max_iter"], random_state=PLAN["seed"], fit_intercept=PLAN["fit_intercept"], class_weight=PLAN["class_weight"])
        with warnings.catch_warnings():
            warnings.simplefilter("error", ConvergenceWarning)
            classifier.fit(features, labels)
        if classifier.classes_.tolist() != [0, 1]:
            raise ValueError("Unexpected classifier class mapping")
        values = classifier.decision_function(vectorizer.transform([source_and_target(r)[0] for r in valid])).tolist()
        margins.update({row["id"]: value for row, value in zip(valid, values, strict=True)})
        parameters[swc] = {"classes": [0, 1], "coefficients": classifier.coef_.tolist(), "intercept": classifier.intercept_.tolist(),
                           "iterations": classifier.n_iter_.tolist(), "training_cases": len(training),
                           "vocabulary": {token: int(index) for token, index in vectorizer.vocabulary_.items()},
                           "idf": vectorizer.idf_.tolist()}
        print(f"SWC-{swc}: trained on {len(training)}, retained validation {len(valid)}", flush=True)
    valid_by_id = {row["id"]: row for row in rows["valid"]}
    subset = [valid_by_id[key] for key in protocol["original_valid_ids"]]
    full = evaluate(rows["valid"], margins)
    original = evaluate(subset, {r["id"]: margins[r["id"]] for r in subset})
    baselines = property_baselines(rows["train"], rows["valid"])
    comparison = {"plan": SCALE_PLAN, "full_validation": full, "original_validation_subset": original,
                  "baselines": baselines, "development_gate": validation_gate(full["scores"], baselines),
                  "training_cases": len(rows["train"]), "validation_cases": len(rows["valid"]),
                  "protocol_sha256": file_hash(output / "protocol.json"),
                  "packages": {name: version(name) for name in ("numpy", "scipy", "scikit-learn")},
                  "independent_99_percent_claim_supported": False, "historical_labels_reviewed": False,
                  "reserved_test_accessed": False, "llm_weights_updated": False,
                  "scope": "Larger lexical control, not LLM performance. No original validation case was dropped. "
                           "Full and subset evaluation share cases and are not independent replications."}
    write_json(output / "classifiers.json", parameters)
    comparison["classifiers_sha256"] = file_hash(output / "classifiers.json")
    write_json(output / "comparison.json", comparison)
    return {"full_validation": {k: full["scores"][k] for k in ("tp", "fp", "tn", "fn", "precision", "recall", "specificity")},
            "development_gate": comparison["development_gate"], "independent_99_percent_claim_supported": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "score"))
    parser.add_argument("--dataset", type=Path, default=ROOT / "datasets/model-properties")
    parser.add_argument("--probe", type=Path, default=ROOT / "training/runs/mac-frozen-probe-v1")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--experimental", action="store_true")
    args = parser.parse_args()
    if args.action == "score" and not args.experimental:
        raise SystemExit("Classifier fitting requires --experimental; historical labels are unreviewed")
    result = prepare(args.dataset, args.probe, args.output) if args.action == "prepare" else score(args.output)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
