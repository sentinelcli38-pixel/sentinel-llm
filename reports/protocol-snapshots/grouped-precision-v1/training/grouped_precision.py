"""Training-only grouped selection for an experimental lexical control, not an LLM."""

import argparse
import json
import math
import sys
import warnings
from collections import Counter, defaultdict
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sentinel.modeling.clones import normalized_tokens
from sentinel.modeling.properties import CGT_REVISION, PROPERTIES
from training.binary_mlx import (
    probability,
    read_development,
    source_and_target,
    write_json,
)
from training.frozen_probe import evaluate
from training.local_model import file_hash
from training.precision_target import assess, verify_report
from training.provisional_review import IMPLEMENTATIONS as REVIEW_CODE
from training.provisional_review import INPUTS, overlay, reconcile, sha

PLAN = {
    "name": "grouped-precision-lexical-v1", "seed": 617, "folds": 3, "scikit_learn": "1.7.2",
    "representations": ["tokens_1_3", "characters_3_5"], "max_features": 16384,
    "C": [0.1, 1.0, 10.0], "class_weight": [None, "balanced"],
    "solver": "LinearSVC", "dual": "auto", "tol": 0.0001, "max_iter": 20000,
    "target_precision": 0.99, "minimum_recall": 0.8, "minimum_specificity": 0.8,
    "selection": "Per property, select on pooled training-only out-of-fold margins. Among points meeting "
                 "all three point targets, maximize recall, precision, specificity, then stable candidate ID. "
                 "If none qualify, retain an explicitly failed-target diagnostic fallback maximizing precision, "
                 "recall, specificity at >=80% recall. Never reduce recall or discard evaluation cases.",
    "grouping": "Global StratifiedGroupKFold on property:label strata and project_group; verify source and "
                "normalized-clone identity separation, both labels per property in fitting and held folds.",
    "scope": "Training-only selection, not nested/unbiased CV, independent testing, calibrated probabilities, "
             "LLM fine-tuning, executable vulnerability proof or production qualification. Full development "
             "validation has been inspected in earlier experiments. Reserved tests remain sealed.",
    "convergence_warning": "Abort and preserve failure; do not silently omit candidates or examples.",
}
IMPLEMENTATIONS = tuple(dict.fromkeys((*REVIEW_CODE, "training/grouped_precision.py")))


def now():
    return datetime.now(UTC).isoformat()


def read_training(dataset: Path) -> tuple[list[dict], dict]:
    # Selection must not even open validation; the broader reader is evaluation-only.
    raw_manifest = (dataset / "manifest.json").read_bytes()
    manifest = json.loads(raw_manifest)
    if manifest.get("source_revision") != CGT_REVISION or manifest.get("task") != "swc_property":
        raise ValueError("Expected the pinned property dataset")
    raw = (dataset / "train.jsonl").read_bytes()
    if sha(raw) != manifest["split_sha256"]["train"]:
        raise ValueError("Training data changed")
    rows = [json.loads(line) for line in raw.splitlines() if line.strip()]
    if len(rows) != manifest["split_counts"]["train"] or len({r["id"] for r in rows}) != len(rows):
        raise ValueError("Training count or unique identities differ")
    identities = {name: {} for name in ("source_hash", "lexical_fingerprint")}
    for row in rows:
        source_and_target(row)
        if any(not isinstance(row.get(key), str) or not row[key] for key in (*identities, "project_group")):
            raise ValueError("Missing training source/group identity")
        for key, seen in identities.items():
            if seen.setdefault(row[key], row["project_group"]) != row["project_group"]:
                raise ValueError("Source or clone identity crosses training groups")
    return rows, {"path": str(dataset.resolve()), "manifest_sha256": sha(raw_manifest),
                  "split_sha256": {k: manifest["split_sha256"][k] for k in ("train", "valid")},
                  "reserved_test_accessed": False}


def review_training(review: Path) -> tuple[list[dict], dict, dict]:
    protocol = json.loads((review / "protocol.json").read_text())
    for name, pin in protocol["implementation_sha256"].items():
        if file_hash(ROOT / name) != pin:
            raise ValueError("Provisional review implementation changed")
    full, pins = read_training(Path(protocol["dataset"]))
    if pins != protocol["input_pins"]:
        raise ValueError("Review training inputs changed")
    probe = Path(protocol["probe"]) / "protocol.json"
    if file_hash(probe) != protocol["probe_pins"][str(probe.resolve())]:
        raise ValueError("Original training selection metadata changed")
    original = json.loads(probe.read_text())
    if original["input_pins"] != pins:
        raise ValueError("Original training selection uses different data")
    selected_ids = original["selection"]["train_ids"]
    index = {r["id"]: r for r in full}
    if len(set(selected_ids)) != len(selected_ids) or not set(selected_ids) <= index.keys():
        raise ValueError("Original selected training identities differ")
    raws = {name: (review / "review-inputs" / filename).read_bytes() for name, filename in INPUTS.items()}
    if {name: sha(raw) for name, raw in raws.items()} != protocol["review_input_sha256"]:
        raise ValueError("Review evidence changed")
    ledger = reconcile(raws, {"train": [index[key] for key in selected_ids]})
    if (file_hash(review / "review-decisions.json") != protocol["ledger_sha256"]
            or json.loads((review / "review-decisions.json").read_text()) != ledger):
        raise ValueError("Provisional label ledger differs from preserved observations")
    training, _ = overlay(full, ledger)
    return training, ledger, pins


def catalog() -> list[dict]:
    return [{"id": f"{representation}-c{c:g}-{'balanced' if weight else 'unweighted'}",
             "representation": representation, "C": c, "class_weight": weight}
            for representation in PLAN["representations"] for c in PLAN["C"] for weight in PLAN["class_weight"]]


def check_folds(rows: list[dict], folds: dict) -> None:
    if len({r["id"] for r in rows}) != len(rows) or {r["id"] for r in rows} != folds.keys():
        raise ValueError("Every training row requires exactly one fold")
    if any(type(f) is not int or not 0 <= f < PLAN["folds"] for f in folds.values()):
        raise ValueError("Invalid fold identity")
    for key in ("project_group", "source_hash", "lexical_fingerprint"):
        seen = {}
        for row in rows:
            if not row.get(key) or seen.setdefault(row[key], folds[row["id"]]) != folds[row["id"]]:
                raise ValueError(f"Fold overlap or missing identity: {key}")
    for fold in range(PLAN["folds"]):
        for swc in PROPERTIES:
            for held in (False, True):
                labels = {source_and_target(r)[1]["vulnerable"] for r in rows
                          if r["swc"] == swc and (folds[r["id"]] == fold) == held}
                if labels != {False, True}:
                    raise ValueError("Each fitting and held fold requires both labels per property")


def make_folds(rows: list[dict]) -> dict:
    from sklearn.model_selection import StratifiedGroupKFold

    splitter = StratifiedGroupKFold(n_splits=PLAN["folds"], shuffle=True, random_state=PLAN["seed"])
    labels = [f"{r['swc']}:{source_and_target(r)[1]['vulnerable']}" for r in rows]
    groups = [r["project_group"] for r in rows]
    folds = {}
    for fold, (_, held) in enumerate(splitter.split(range(len(rows)), labels, groups)):
        for index in held:
            folds[rows[index]["id"]] = fold
    check_folds(rows, folds)
    return folds


def prepare(review: Path, output: Path) -> dict:
    if output.exists():
        raise FileExistsError("Use a fresh output directory; preserve previous experiments")
    if version("scikit-learn") != PLAN["scikit_learn"]:
        raise ValueError("Install the pinned optional probe dependencies")
    rows, ledger, pins = review_training(review)
    if any(output.resolve().is_relative_to(p.resolve()) for p in (review, Path(pins["path"]))):
        raise ValueError("Do not write inside original inputs")
    folds = make_folds(rows)
    protocol = {"plan": PLAN, "catalog": catalog(), "created_at": now(), "review": str(review.resolve()),
                "review_protocol_sha256": file_hash(review / "protocol.json"), "input_pins": pins,
                "ledger_sha256": file_hash(review / "review-decisions.json"),
                "approval_report": ledger["approval_report"], "signed_human_consensus": False,
                "training_ids": [r["id"] for r in rows], "training_cases": len(rows),
                "withheld_training_cases": ledger["withheld_from_training"], "folds": folds,
                "training_buckets": dict(sorted(Counter(f"{r['swc']}:{source_and_target(r)[1]['vulnerable']}" for r in rows).items())),
                "implementation_sha256": {name: file_hash(ROOT / name) for name in IMPLEMENTATIONS},
                "validation_accessed_during_selection": False, "reserved_test_accessed": False}
    output.mkdir(parents=True)
    write_json(output / "protocol.json", protocol)
    write_json(output / "review-decisions.json", ledger)
    return {"training_cases": len(rows), "candidates_per_property": len(catalog()), "folds": PLAN["folds"],
            "withheld_training_cases": ledger["withheld_from_training"], "validation_accessed": False}


def load_training(output: Path) -> tuple[dict, list[dict]]:
    protocol = json.loads((output / "protocol.json").read_text())
    if (protocol["plan"] != PLAN or protocol["catalog"] != catalog()
            or set(protocol["implementation_sha256"]) != set(IMPLEMENTATIONS)):
        raise ValueError("Frozen selection protocol differs")
    for name, pin in protocol["implementation_sha256"].items():
        if file_hash(ROOT / name) != pin:
            raise ValueError("Selection implementation changed")
    review = Path(protocol["review"])
    if file_hash(review / "protocol.json") != protocol["review_protocol_sha256"]:
        raise ValueError("Review protocol changed")
    rows, ledger, pins = review_training(review)
    if (pins != protocol["input_pins"] or protocol["training_ids"] != [r["id"] for r in rows]
            or protocol["training_cases"] != len(rows) or protocol["withheld_training_cases"] != ledger["withheld_from_training"]
            or protocol["approval_report"] != ledger["approval_report"]
            or file_hash(output / "review-decisions.json") != protocol["ledger_sha256"]
            or json.loads((output / "review-decisions.json").read_text()) != ledger):
        raise ValueError("Training cohort or review provenance changed")
    check_folds(rows, protocol["folds"])
    return protocol, rows


def counts(tp, fp, positives, negatives) -> dict:
    return {"tp": tp, "fp": fp, "tn": negatives - fp, "fn": positives - tp,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / positives, "specificity": (negatives - fp) / negatives}


def choose_threshold(labels: list[bool], margins: list[float]) -> dict:
    if (len(labels) != len(margins) or not labels or any(type(v) is not bool for v in labels)
            or set(labels) != {False, True}
            or any(type(v) not in (int, float) or not math.isfinite(v) for v in margins)):
        raise ValueError("Both labels and finite aligned training OOF margins required")
    groups = defaultdict(list)
    for truth, margin in zip(labels, margins, strict=True):
        groups[margin].append(truth)
    scores = sorted(groups, reverse=True)
    positives, negatives = sum(labels), len(labels) - sum(labels)
    eligible, tp, fp = [], 0, 0
    for i, score in enumerate(scores):
        tp += sum(groups[score])
        fp += len(groups[score]) - sum(groups[score])
        # Midpoints keep tied examples together; no threshold is chosen on validation.
        threshold = score / 2 + scores[i + 1] / 2 if i + 1 < len(scores) else score - max(1.0, abs(score))
        if not math.isfinite(threshold) or threshold >= score:
            raise ValueError("Unable to represent a finite strict decision boundary")
        point = {"threshold": threshold, **counts(tp, fp, positives, negatives)}
        if point["recall"] >= PLAN["minimum_recall"]:
            eligible.append(point)
    feasible = [p for p in eligible if p["precision"] >= PLAN["target_precision"]
                and p["specificity"] >= PLAN["minimum_specificity"]]
    key = (lambda p: (p["recall"], p["precision"], p["specificity"], p["threshold"])) if feasible else (
        lambda p: (p["precision"], p["recall"], p["specificity"], p["threshold"]))
    best = max(feasible or eligible, key=key)
    actual = [probability([0.0, m - best["threshold"]]) > 0.5 for m in margins]
    check = counts(sum(t and p for t, p in zip(labels, actual, strict=True)),
                   sum(not t and p for t, p in zip(labels, actual, strict=True)), positives, negatives)
    if any(check[k] != best[k] for k in check):
        raise ValueError("Threshold comparison is not numerically reproducible")
    return {**best, "point_target_feasible": bool(feasible), "eligible_thresholds": len(eligible)}


def select_candidate(candidates: list[dict]) -> dict:
    if not candidates or len({c["id"] for c in candidates}) != len(candidates):
        raise ValueError("Unique candidate evidence is required")
    feasible = [c for c in candidates if c["selection"]["point_target_feasible"]]
    ordered = sorted(feasible or candidates, key=lambda c: c["id"])
    names = ("recall", "precision", "specificity") if feasible else ("precision", "recall", "specificity")
    best = max(ordered, key=lambda c: tuple(c["selection"][name] for name in names))
    return {"candidate": best["id"], **best["selection"],
            "status": "training_point_targets_met" if feasible else "failed_target_diagnostic_fallback"}


def vectorizer(representation: str, vocabulary=None, idf=None):
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer

    if representation not in PLAN["representations"]:
        raise ValueError("Unknown frozen representation")
    options = {"lowercase": False, "max_features": PLAN["max_features"], "vocabulary": vocabulary,
               "dtype": np.float64, "norm": "l2", "sublinear_tf": False, "smooth_idf": True}
    if representation == "tokens_1_3":
        options.update(analyzer="word", tokenizer=normalized_tokens, token_pattern=None, ngram_range=(1, 3))
    else:
        options.update(analyzer="char", ngram_range=(3, 5))
    result = TfidfVectorizer(**options)
    if idf is not None:
        result.idf_ = np.asarray(idf, dtype=np.float64)
    return result


def classifier(candidate: dict):
    from sklearn.svm import LinearSVC

    return LinearSVC(C=candidate["C"], class_weight=candidate["class_weight"], dual=PLAN["dual"],
                     random_state=PLAN["seed"], tol=PLAN["tol"], max_iter=PLAN["max_iter"])


def export_model(candidate: dict, selected: dict, vec, model) -> dict:
    return {"candidate": candidate, "threshold": selected["threshold"], "classes": model.classes_.tolist(),
            "vocabulary": {k: int(v) for k, v in vec.vocabulary_.items()}, "idf": vec.idf_.tolist(),
            "coefficient": model.coef_[0].tolist(), "intercept": float(model.intercept_[0]),
            "iterations": int(model.n_iter_), "score_is_calibrated_probability": False}


def replay(model: dict, sources: list[str]) -> list[float]:
    import numpy as np

    vocab, idf, coefficients = model["vocabulary"], model["idf"], model["coefficient"]
    if (model["classes"] != [0, 1] or not vocab or len(idf) != len(vocab) or len(coefficients) != len(vocab)
            or set(vocab.values()) != set(range(len(vocab)))
            or any(type(i) is not int for i in vocab.values())
            or any(type(v) not in (int, float) or not math.isfinite(v)
                   for v in [*idf, *coefficients, model["intercept"], model["threshold"]])
            or any(v <= 0 for v in idf)):
        raise ValueError("Malformed or nonfinite JSON classifier")
    vec = vectorizer(model["candidate"]["representation"], vocab, idf)
    margins = vec.transform(sources) @ np.asarray(coefficients) + model["intercept"] - model["threshold"]
    if not np.isfinite(margins).all():
        raise ValueError("Nonfinite replay margins")
    return margins.tolist()


def fit(output: Path) -> dict:
    if any((output / name).exists() for name in ("fit-started.json", "selection.json", "models.json", "fit.json")):
        raise FileExistsError("Fit already attempted; preserve its evidence")
    protocol, rows = load_training(output)
    if version("scikit-learn") != PLAN["scikit_learn"]:
        raise ValueError("Optional scikit-learn version differs")
    import numpy as np
    from sklearn.exceptions import ConvergenceWarning

    write_json(output / "fit-started.json", {"started_at": now(), "protocol_sha256": file_hash(output / "protocol.json")})
    evidence, models, selected = {}, {}, {}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", ConvergenceWarning)
            for swc in PROPERTIES:
                subset = [r for r in rows if r["swc"] == swc]
                sources = [source_and_target(r)[0] for r in subset]
                labels = [source_and_target(r)[1]["vulnerable"] for r in subset]
                folds = np.asarray([protocol["folds"][r["id"]] for r in subset])
                candidates = [{**c, "margins": [None] * len(subset)} for c in catalog()]
                for representation in PLAN["representations"]:
                    for fold in range(PLAN["folds"]):
                        ti, vi = np.flatnonzero(folds != fold), np.flatnonzero(folds == fold)
                        vec = vectorizer(representation)
                        x_train = vec.fit_transform([sources[i] for i in ti])
                        x_held = vec.transform([sources[i] for i in vi])
                        for candidate in candidates:
                            if candidate["representation"] != representation:
                                continue
                            model = classifier(candidate).fit(x_train, [int(labels[i]) for i in ti])
                            for i, margin in zip(vi, model.decision_function(x_held).tolist(), strict=True):
                                if candidate["margins"][i] is not None:
                                    raise ValueError("Duplicate OOF assessment")
                                candidate["margins"][i] = margin
                        print(f"SWC-{swc} {representation} fold {fold + 1}/{PLAN['folds']} completed", flush=True)
                for candidate in candidates:
                    candidate["selection"] = choose_threshold(labels, candidate["margins"])
                selected[swc] = select_candidate(candidates)
                evidence[swc] = {"ids": [r["id"] for r in subset], "labels": labels, "candidates": candidates}
                chosen = next(c for c in catalog() if c["id"] == selected[swc]["candidate"])
                vec = vectorizer(chosen["representation"])
                x_full = vec.fit_transform(sources)
                model = classifier(chosen).fit(x_full, [int(label) for label in labels])
                exported = export_model(chosen, selected[swc], vec, model)
                if not np.allclose(replay(exported, sources), model.decision_function(x_full) - selected[swc]["threshold"],
                                   atol=1e-10, rtol=1e-10):
                    raise ValueError("Saved JSON model does not reproduce training margins")
                models[swc] = exported
                # Preserve completed properties even if a later property fails.
                write_json(output / f"oof-{swc}.json", evidence[swc])
                print(f"SWC-{swc} selection: {json.dumps(selected[swc])}", flush=True)
        write_json(output / "models.json", models)
        write_json(output / "selection.json", {"selected": selected, "selection_data": "training-only pooled OOF",
            "scope": PLAN["scope"], "validation_accessed": False, "point_targets_met_for_every_property":
            all(v["point_target_feasible"] for v in selected.values())})
        receipt = {"status": "completed", "completed_at": now(), "protocol_sha256": file_hash(output / "protocol.json"),
                   "artifact_sha256": {name: file_hash(output / name) for name in
                                      ("models.json", "selection.json", *(f"oof-{swc}.json" for swc in PROPERTIES))},
                   "runtime_versions": {name: version(name) for name in ("scikit-learn", "numpy", "scipy")},
                   "validation_accessed": False, "reserved_test_accessed": False}
        write_json(output / "fit.json", receipt)
        return selected
    except Exception as exc:
        write_json(output / "fit-failure.json", {"status": "failed", "at": now(), "error": f"{type(exc).__name__}: {exc}",
                                                "completed_properties": list(models), "validation_accessed": False})
        raise


def evaluate_frozen(output: Path) -> dict:
    if any((output / name).exists() for name in ("evaluation-started.json", "comparison.json")):
        raise FileExistsError("Evaluation already attempted; do not tune or overwrite results")
    protocol, training = load_training(output)
    receipt = json.loads((output / "fit.json").read_text())
    required = {"models.json", "selection.json", *(f"oof-{swc}.json" for swc in PROPERTIES)}
    if (receipt.get("status") != "completed" or receipt["protocol_sha256"] != file_hash(output / "protocol.json")
            or receipt.get("validation_accessed") is not False or set(receipt["artifact_sha256"]) != required):
        raise ValueError("Completed training-only fit receipt required before validation")
    for name, pin in receipt["artifact_sha256"].items():
        if file_hash(output / name) != pin:
            raise ValueError("Frozen selected model or OOF evidence changed")
    if any(version(name) != pinned for name, pinned in receipt["runtime_versions"].items()):
        raise ValueError("Evaluation runtime differs from the frozen fit")
    models = json.loads((output / "models.json").read_text())
    selection = json.loads((output / "selection.json").read_text())
    if models.keys() != PROPERTIES.keys() or selection["selected"].keys() != PROPERTIES.keys():
        raise ValueError("All properties must remain in evaluation")
    for swc, model in models.items():
        if (model["threshold"] != selection["selected"][swc]["threshold"]
                or model["candidate"]["id"] != selection["selected"][swc]["candidate"]):
            raise ValueError("Selected decision boundaries differ")
    # This receipt precedes the first validation read, not just the first reported score.
    write_json(output / "evaluation-started.json", {"started_at": now(), "fit_sha256": file_hash(output / "fit.json"),
                                                  "protocol_sha256": file_hash(output / "protocol.json")})
    try:
        full, pins = read_development(Path(protocol["input_pins"]["path"]))
        if pins != protocol["input_pins"]:
            raise ValueError("Evaluation inputs differ from the predeclared manifest")
        valid = full["valid"]
        if {r["id"] for r in training} & {r["id"] for r in valid}:
            raise ValueError("Training/evaluation identity overlap")
        margins = {}
        for swc, model in models.items():
            subset = [r for r in valid if r["swc"] == swc]
            if not subset:
                raise ValueError("Missing validation property")
            margins.update(zip([r["id"] for r in subset], replay(model, [source_and_target(r)[0] for r in subset]), strict=True))
        report = evaluate(valid, margins)
        verify_report(report, valid)
        scores = report["scores"]
        point_checks = {"overall": scores, **scores["per_swc"]}
        point_target = all(r["precision"] is not None and r["precision"] >= PLAN["target_precision"]
                           and r["recall"] >= PLAN["minimum_recall"] and r["specificity"] >= PLAN["minimum_specificity"]
                           for r in point_checks.values())
        result = {"full_validation": report, "target_audit": assess(scores), "point_target_met": point_target,
                  "training_cases": len(training), "validation_cases": len(valid), "selection": selection,
                  "protocol_sha256": file_hash(output / "protocol.json"), "fit_sha256": file_hash(output / "fit.json"),
                  "completed_at": now(), "validation_labels_changed": False, "llm_weights_updated": False,
                  "live_detector_changed": False, "reserved_test_accessed": False, "scope": PLAN["scope"]}
        write_json(output / "comparison.json", result)
        return {"scores": scores, "point_target_met": point_target,
                "numerical_requirements_met": result["target_audit"]["numerical_requirements_met"]}
    except Exception as exc:
        write_json(output / "evaluation-failure.json", {"at": now(), "error": f"{type(exc).__name__}: {exc}"})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("prepare", "fit", "evaluate"))
    parser.add_argument("--review", type=Path, default=ROOT / "training/runs/mac-provisional-review-v1")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--experimental", action="store_true", required=True)
    args = parser.parse_args()
    result = prepare(args.review, args.output) if args.stage == "prepare" else (
        fit(args.output) if args.stage == "fit" else evaluate_frozen(args.output))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
