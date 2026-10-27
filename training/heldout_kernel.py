"""Nonlinear code-similarity control with an unchanged model after threshold selection."""

import argparse
import gzip
import io
import json
import math
import sys
import warnings
from collections import defaultdict
from importlib.metadata import version
from itertools import pairwise
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from training import grouped_precision as gp
from training.binary_mlx import wilson_interval

PLAN = {
    "name": "heldout-threshold-kernel-v1", "seed": 811, "scikit_learn": "1.7.2",
    "threshold_fold": 2, "inner_folds": 3, "representations": ["tokens_1_3", "characters_3_5"],
    "C": [1.0, 10.0], "class_weight": "balanced", "gamma": 1.0, "max_features": 8192,
    "kernel": "RBF precomputed using sklearn", "max_iter": 100000, "tol": 0.0001,
    "score_decimal_places": 12, "target_precision": 0.99, "minimum_recall": 0.8, "minimum_specificity": 0.8,
    "selection": gp.PLAN["selection"],
    "roles": "Anchor folds 0/1 fit models; fold 2 sets thresholds only. Select candidates in three grouped "
             "inner folds of model-fit rows, then refit the chosen procedure on those rows only. "
             "Freeze models before threshold scoring; never refit on threshold rows or validation.",
    "features": "Whole-source TF-IDF, normalized token 1-3 grams or case-sensitive character 3-5 grams. "
                "Fit vocabulary and IDF on each fitting subset only; no source, row or property exclusions. "
                "Character features retain identifiers and compiler cues, not semantic proof or target isolation.",
    "score": "Round sigmoid(decision margin) to 12 decimals. This monotonic reporting scale is not a calibrated "
             "vulnerability probability. Store raw OOF margins and all candidate outcomes.",
    "scope": "Exploratory development, not LLM fine-tuning or independent testing. Validation was inspected in "
             "earlier experiments. Original labels, review provenance and all evaluation cases retained. "
             "No live-detector promotion, reserved test access or guarantee of 99% precision.",
}
IMPLEMENTATIONS = (*gp.IMPLEMENTATIONS, "training/heldout_kernel.py", "training/requirements-probe.txt")


def catalog():
    return [{"id": f"{representation}-rbf-c{c:g}", "representation": representation, "C": c}
            for representation in PLAN["representations"] for c in PLAN["C"]]


def scores_from_margins(values):
    if any(type(v) not in (int, float) or not math.isfinite(v) for v in values):
        raise ValueError("Finite decision margins required")
    return [round(gp.probability([0.0, value]), PLAN["score_decimal_places"]) for value in values]


def training_audit(rows):
    exact, normalized = defaultdict(list), defaultdict(list)
    fingerprints = {}
    for row in rows:
        source, target = gp.source_and_target(row)
        source_hash = row["source_hash"]
        if source_hash not in fingerprints:
            fingerprints[source_hash] = gp.sha(" ".join(gp.normalized_tokens(source)).encode())
        exact[(row["swc"], source_hash, row["contract"])].append((row["id"], target["vulnerable"]))
        normalized[(row["swc"], fingerprints[source_hash])].append((row["id"], target["vulnerable"]))
    results = {}
    for name, buckets in (("exact_source_target", exact), ("normalized_whole_source", normalized)):
        mixed = [{"swc": key[0], "ids": [r[0] for r in values], "positives": sum(r[1] for r in values),
                  "negatives": sum(not r[1] for r in values)} for key, values in buckets.items()
                 if len({r[1] for r in values}) > 1]
        results[name] = {"unique_inputs": len(buckets), "mixed_groups": mixed,
                         "mixed_rows": sum(r["positives"] + r["negatives"] for r in mixed)}
    return {"training_rows": len(rows), "results": results,
            "rows_without_explicit_compiler_or_dependency_lock": sum(not r.get("compiler_version") or not r.get("dependency_lock") for r in rows),
            "scope": "Training-only diagnostic. Feature collisions do not establish incorrect human labels; "
                     "different identifiers/literals/context may distinguish programs. No labels changed."}


def partition(rows, folds):
    gp.check_folds(rows, folds)
    fit = [r for r in rows if folds[r["id"]] != PLAN["threshold_fold"]]
    threshold = [r for r in rows if folds[r["id"]] == PLAN["threshold_fold"]]
    for swc in gp.PROPERTIES:
        for items in (fit, threshold):
            if {gp.source_and_target(r)[1]["vulnerable"] for r in items if r["swc"] == swc} != {False, True}:
                raise ValueError("Each role needs both labels for every property")
    return fit, threshold


def inner_folds(rows):
    from sklearn.model_selection import StratifiedGroupKFold

    splitter = StratifiedGroupKFold(n_splits=PLAN["inner_folds"], shuffle=True, random_state=PLAN["seed"])
    strata = [f"{r['swc']}:{gp.source_and_target(r)[1]['vulnerable']}" for r in rows]
    groups = [r["project_group"] for r in rows]
    result = {}
    for fold, (_, held) in enumerate(splitter.split(range(len(rows)), strata, groups)):
        for i in held:
            result[rows[i]["id"]] = fold
    gp.check_folds(rows, result)
    return result


def prepare(anchor: Path, output: Path):
    if output.exists():
        raise FileExistsError("Use a fresh output directory; preserve prior attempts")
    original, rows = gp.load_training(anchor)
    if any(output.resolve().is_relative_to(p.resolve()) for p in (anchor, Path(original["input_pins"]["path"]), Path(original["review"]))):
        raise ValueError("Keep new output outside original inputs")
    if version("scikit-learn") != PLAN["scikit_learn"]:
        raise ValueError("Install the pinned optional probe dependencies")
    fit, threshold = partition(rows, original["folds"])
    folds = inner_folds(fit)
    audit = training_audit(rows)
    output.mkdir(parents=True)
    gp.write_json(output / "training-audit.json", audit)
    protocol = {"plan": PLAN, "catalog": catalog(), "created_at": gp.now(), "anchor": str(anchor.resolve()),
                "anchor_protocol_sha256": gp.file_hash(anchor / "protocol.json"), "input_pins": original["input_pins"],
                "approval_report": original["approval_report"], "withheld_training_cases": original["withheld_training_cases"],
                "model_fit_ids": [r["id"] for r in fit], "threshold_ids": [r["id"] for r in threshold], "inner_folds": folds,
                "training_audit_sha256": gp.file_hash(output / "training-audit.json"),
                "implementation_sha256": {name: gp.file_hash(ROOT / name) for name in IMPLEMENTATIONS},
                "validation_accessed_during_selection": False, "reserved_test_accessed": False}
    gp.write_json(output / "protocol.json", protocol)
    return {"model_fit_rows": len(fit), "threshold_rows": len(threshold), "candidates_per_property": len(catalog())}


def load_training(output):
    protocol = json.loads((output / "protocol.json").read_text())
    if protocol["plan"] != PLAN or protocol["catalog"] != catalog() or set(protocol["implementation_sha256"]) != set(IMPLEMENTATIONS):
        raise ValueError("Heldout-kernel protocol changed")
    for name, pin in protocol["implementation_sha256"].items():
        if gp.file_hash(ROOT / name) != pin:
            raise ValueError("Frozen implementation changed")
    anchor = Path(protocol["anchor"])
    if gp.file_hash(anchor / "protocol.json") != protocol["anchor_protocol_sha256"]:
        raise ValueError("Training-only anchor changed")
    original, rows = gp.load_training(anchor)
    fit, threshold = partition(rows, original["folds"])
    if (protocol["model_fit_ids"] != [r["id"] for r in fit] or protocol["threshold_ids"] != [r["id"] for r in threshold]
            or protocol["input_pins"] != original["input_pins"] or protocol["approval_report"] != original["approval_report"]
            or protocol["withheld_training_cases"] != original["withheld_training_cases"]
            or gp.file_hash(output / "training-audit.json") != protocol["training_audit_sha256"]):
        raise ValueError("Training roles, inputs or provenance changed")
    gp.check_folds(fit, protocol["inner_folds"])
    return protocol, fit, threshold


def vectorizer(representation, vocabulary=None, idf=None):
    result = gp.vectorizer(representation, vocabulary, idf)
    result.set_params(max_features=PLAN["max_features"])
    return result


def estimator(candidate):
    from sklearn.svm import SVC

    return SVC(kernel="precomputed", C=candidate["C"], class_weight=PLAN["class_weight"],
               probability=False, tol=PLAN["tol"], max_iter=PLAN["max_iter"], cache_size=128)


def kernel(left, right):
    import numpy as np
    from sklearn.metrics.pairwise import rbf_kernel

    result = rbf_kernel(left, right, gamma=PLAN["gamma"])
    if not np.isfinite(result).all():
        raise ValueError("Nonfinite similarity kernel")
    return result


def export_model(candidate, vec, fitted, x_train):
    support = x_train[fitted.support_].tocsr()
    return {"candidate": candidate, "classes": fitted.classes_.tolist(),
            "vocabulary": {k: int(v) for k, v in vec.vocabulary_.items()}, "idf": vec.idf_.tolist(),
            "support": {"shape": list(support.shape), "indptr": support.indptr.tolist(),
                        "indices": support.indices.tolist(), "data": support.data.tolist()},
            "dual": fitted.dual_coef_[0].tolist(), "intercept": float(fitted.intercept_[0]),
            "gamma": PLAN["gamma"], "probability_calibrated": False}


def replay_margins(model, sources):
    import numpy as np
    from scipy.sparse import csr_matrix

    data = model["support"]
    shape, indices, indptr = data["shape"], data["indices"], data["indptr"]
    if (model["classes"] != [0, 1] or model["gamma"] != PLAN["gamma"] or len(shape) != 2
            or any(type(n) is not int or n < 1 for n in shape)
            or len(indptr) != shape[0] + 1 or not indptr or indptr[0] != 0 or indptr[-1] != len(data["data"])
            or len(indices) != len(data["data"]) or len(model["dual"]) != shape[0]
            or any(type(n) is not int or not 0 <= n < shape[1] for n in indices)
            or any(type(n) is not int or not 0 <= n <= len(indices) for n in indptr)
            or any(a > b for a, b in pairwise(indptr))
            or shape[1] != len(model["vocabulary"]) or shape[1] != len(model["idf"])
            or set(model["vocabulary"].values()) != set(range(shape[1]))
            or any(type(v) not in (int, float) or not math.isfinite(v)
                   for v in [*data["data"], *model["dual"], *model["idf"], model["intercept"]])
            or any(v < 0 for v in data["data"]) or any(v <= 0 for v in model["idf"])):
        raise ValueError("Malformed or nonfinite JSON kernel model")
    support = csr_matrix((np.asarray(data["data"]), np.asarray(indices), np.asarray(indptr)), shape=tuple(shape))
    vec = vectorizer(model["candidate"]["representation"], model["vocabulary"], model["idf"])
    x = vec.transform(sources)
    margins = kernel(x, support) @ np.asarray(model["dual"]) + model["intercept"]
    if not np.isfinite(margins).all():
        raise ValueError("Nonfinite replay margins")
    return margins.tolist()


def save_models(path, models):
    with (path.open("xb") as raw,
          gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed,
          io.TextIOWrapper(compressed, encoding="utf-8") as text):
        json.dump(models, text, separators=(",", ":"), allow_nan=False)


def read_models(path):
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        return json.load(handle)


def check_versions(versions):
    if any(version(name) != pin for name, pin in versions.items()):
        raise ValueError("Runtime differs from the frozen fit")


def fit(output):
    if any((output / name).exists() for name in ("fit-started.json", "models.json.gz", "fitted.json")):
        raise FileExistsError("Fit already attempted; preserve evidence")
    protocol, rows, _threshold_rows = load_training(output)
    if version("scikit-learn") != PLAN["scikit_learn"]:
        raise ValueError("Wrong optional scikit-learn version")
    import numpy as np
    from sklearn.exceptions import ConvergenceWarning

    gp.write_json(output / "fit-started.json", {"started_at": gp.now(), "protocol_sha256": gp.file_hash(output / "protocol.json")})
    models, selected = {}, {}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", ConvergenceWarning)
            for swc in gp.PROPERTIES:
                subset = [r for r in rows if r["swc"] == swc]
                sources = [gp.source_and_target(r)[0] for r in subset]
                labels = [gp.source_and_target(r)[1]["vulnerable"] for r in subset]
                folds = np.asarray([protocol["inner_folds"][r["id"]] for r in subset])
                candidates = [{**c, "raw_margins": [None] * len(subset)} for c in catalog()]
                for representation in PLAN["representations"]:
                    for fold in range(PLAN["inner_folds"]):
                        ti, vi = np.flatnonzero(folds != fold), np.flatnonzero(folds == fold)
                        vec = vectorizer(representation)
                        x_train = vec.fit_transform([sources[i] for i in ti])
                        x_held = vec.transform([sources[i] for i in vi])
                        train_kernel, held_kernel = kernel(x_train, x_train), kernel(x_held, x_train)
                        for candidate in candidates:
                            if candidate["representation"] != representation:
                                continue
                            fitted = estimator(candidate).fit(train_kernel, [int(labels[i]) for i in ti])
                            if fitted.fit_status_ != 0:
                                raise ValueError("Kernel solver did not converge")
                            for i, margin in zip(vi, fitted.decision_function(held_kernel).tolist(), strict=True):
                                if candidate["raw_margins"][i] is not None:
                                    raise ValueError("Duplicate OOF assessment")
                                candidate["raw_margins"][i] = margin
                        print(f"SWC-{swc} {representation} inner fold {fold + 1}/3", flush=True)
                for candidate in candidates:
                    candidate["scores"] = scores_from_margins(candidate["raw_margins"])
                    candidate["selection"] = gp.choose_threshold(labels, candidate["scores"])
                selected[swc] = gp.select_candidate(candidates)
                gp.write_json(output / f"oof-{swc}.json", {"ids": [r["id"] for r in subset], "labels": labels, "candidates": candidates})
                chosen = next(c for c in catalog() if c["id"] == selected[swc]["candidate"])
                vec = vectorizer(chosen["representation"])
                x_train = vec.fit_transform(sources)
                fitted = estimator(chosen).fit(kernel(x_train, x_train), [int(t) for t in labels])
                if fitted.fit_status_ != 0:
                    raise ValueError("Selected kernel solver did not converge")
                model = export_model(chosen, vec, fitted, x_train)
                if not np.allclose(replay_margins(model, sources), fitted.decision_function(kernel(x_train, x_train)), atol=1e-10, rtol=1e-10):
                    raise ValueError("JSON support vectors do not reproduce sklearn")
                models[swc] = model
                print(f"SWC-{swc} model selection: {json.dumps(selected[swc])}", flush=True)
        save_models(output / "models.json.gz", models)
        gp.write_json(output / "candidate-selection.json", {"selected": selected, "data_role": "model-fit inner OOF only",
                                                          "threshold_holdout_used_for_candidate_choice": False})
        artifacts = ["models.json.gz", "candidate-selection.json", *(f"oof-{swc}.json" for swc in gp.PROPERTIES)]
        gp.write_json(output / "fitted.json", {"status": "completed", "completed_at": gp.now(),
            "protocol_sha256": gp.file_hash(output / "protocol.json"),
            "artifact_sha256": {name: gp.file_hash(output / name) for name in artifacts},
            "runtime_versions": {name: version(name) for name in ("scikit-learn", "numpy", "scipy")},
            "threshold_scores_used": False, "validation_accessed": False, "reserved_test_accessed": False})
        return selected
    except Exception as exc:
        gp.write_json(output / "fit-failure.json", {"at": gp.now(), "error": f"{type(exc).__name__}: {exc}", "completed_properties": list(models)})
        raise


def load_fitted(output):
    protocol, fit_rows, threshold_rows = load_training(output)
    receipt = json.loads((output / "fitted.json").read_text())
    required = {"models.json.gz", "candidate-selection.json", *(f"oof-{swc}.json" for swc in gp.PROPERTIES)}
    if (receipt["status"] != "completed" or receipt["protocol_sha256"] != gp.file_hash(output / "protocol.json")
            or receipt["threshold_scores_used"] is not False or receipt["validation_accessed"] is not False
            or set(receipt["artifact_sha256"]) != required):
        raise ValueError("Completed model-fit receipt required")
    for name, pin in receipt["artifact_sha256"].items():
        if gp.file_hash(output / name) != pin:
            raise ValueError("Frozen model or selection evidence changed")
    check_versions(receipt["runtime_versions"])
    models = read_models(output / "models.json.gz")
    selection = json.loads((output / "candidate-selection.json").read_text())["selected"]
    if models.keys() != gp.PROPERTIES.keys() or selection.keys() != gp.PROPERTIES.keys():
        raise ValueError("All four properties required")
    if any(model["candidate"]["id"] != selection[swc]["candidate"] for swc, model in models.items()):
        raise ValueError("Selected kernel models differ")
    return protocol, fit_rows, threshold_rows, models


def choose_thresholds(output):
    if any((output / name).exists() for name in ("threshold-started.json", "thresholds.json")):
        raise FileExistsError("Threshold selection already attempted; preserve its result")
    _protocol, _fit_rows, rows, models = load_fitted(output)
    before = gp.file_hash(output / "models.json.gz")
    gp.write_json(output / "threshold-started.json", {"started_at": gp.now(), "fitted_sha256": gp.file_hash(output / "fitted.json"), "models_sha256": before})
    try:
        results = {}
        for swc, model in models.items():
            subset = [r for r in rows if r["swc"] == swc]
            labels = [gp.source_and_target(r)[1]["vulnerable"] for r in subset]
            raw = replay_margins(model, [gp.source_and_target(r)[0] for r in subset])
            scores = scores_from_margins(raw)
            selected = gp.choose_threshold(labels, scores)
            results[swc] = {"ids": [r["id"] for r in subset], "labels": labels, "raw_margins": raw, "scores": scores,
                            "selected": selected, "status": "point_targets_met" if selected["point_target_feasible"] else "failed_target_diagnostic_fallback"}
        if gp.file_hash(output / "models.json.gz") != before:
            raise ValueError("Model changed during threshold selection")
        document = {"results": results, "completed_at": gp.now(), "data_role": "separate training threshold holdout",
                    "models_sha256": before, "fitted_sha256": gp.file_hash(output / "fitted.json"),
                    "model_refitted": False, "validation_accessed": False, "reserved_test_accessed": False}
        gp.write_json(output / "thresholds.json", document)
        return {swc: value["selected"] for swc, value in results.items()}
    except Exception as exc:
        gp.write_json(output / "threshold-failure.json", {"at": gp.now(), "error": f"{type(exc).__name__}: {exc}"})
        raise


def best_case_support(rows):
    minimum = 1
    while wilson_interval(minimum, minimum)["lower"] < 0.99:
        minimum += 1
    result = {}
    for scope in ("overall", *gp.PROPERTIES):
        positives = sum(gp.source_and_target(r)[1]["vulnerable"] for r in rows if scope == "overall" or r["swc"] == scope)
        interval = wilson_interval(positives, positives)
        result[scope] = {"available_positives": positives, "best_case_precision_interval": interval,
                         "existing_99_interval_rule_possible": interval["lower"] is not None and interval["lower"] >= 0.99,
                         "additional_zero_false_positive_flags_for_nominal_rule": max(0, minimum - positives)}
    return {"minimum_perfect_positive_flags_for_existing_nominal_rule": minimum, "scopes": result,
            "scope": "Optimistic sample-support ceiling, not predicted performance. A 99% observed point estimate "
                     "is different from a 99% lower interval bound. Correlated sources need stronger sampling evidence."}


def evaluate_frozen(output):
    if any((output / name).exists() for name in ("evaluation-started.json", "comparison.json")):
        raise FileExistsError("Evaluation already attempted; no repeated threshold adjustment")
    protocol, fit_rows, threshold_rows, models = load_fitted(output)
    thresholds = json.loads((output / "thresholds.json").read_text())
    if (thresholds["models_sha256"] != gp.file_hash(output / "models.json.gz")
            or thresholds["fitted_sha256"] != gp.file_hash(output / "fitted.json")
            or thresholds["model_refitted"] is not False or thresholds["validation_accessed"] is not False
            or thresholds["results"].keys() != gp.PROPERTIES.keys()):
        raise ValueError("Frozen threshold holdout receipt required")
    for swc, saved in thresholds["results"].items():
        subset = [r for r in threshold_rows if r["swc"] == swc]
        if (saved["ids"] != [r["id"] for r in subset] or saved["labels"] != [gp.source_and_target(r)[1]["vulnerable"] for r in subset]
                or saved["scores"] != scores_from_margins(saved["raw_margins"])
                or saved["selected"] != gp.choose_threshold(saved["labels"], saved["scores"])):
            raise ValueError("Threshold evidence differs")
        current = scores_from_margins(replay_margins(models[swc], [gp.source_and_target(r)[0] for r in subset]))
        if current != saved["scores"]:
            raise ValueError("Threshold holdout model scores differ")
    gp.write_json(output / "evaluation-started.json", {"started_at": gp.now(), "thresholds_sha256": gp.file_hash(output / "thresholds.json"),
                                                     "models_sha256": gp.file_hash(output / "models.json.gz")})
    try:
        full, pins = gp.read_development(Path(protocol["input_pins"]["path"]))
        if pins != protocol["input_pins"]:
            raise ValueError("Evaluation data changed")
        valid, margins = full["valid"], {}
        for swc, model in models.items():
            subset = [r for r in valid if r["swc"] == swc]
            if not subset:
                raise ValueError("Missing validation property")
            scores = scores_from_margins(replay_margins(model, [gp.source_and_target(r)[0] for r in subset]))
            threshold = thresholds["results"][swc]["selected"]["threshold"]
            margins.update({r["id"]: score - threshold for r, score in zip(subset, scores, strict=True)})
        report = gp.evaluate(valid, margins)
        gp.verify_report(report, valid)
        scores = report["scores"]
        point_target = all(s["precision"] is not None and s["precision"] >= PLAN["target_precision"]
                           and s["recall"] >= PLAN["minimum_recall"] and s["specificity"] >= PLAN["minimum_specificity"]
                           for s in (scores, *scores["per_swc"].values()))
        gp.write_json(output / "comparison.json", {"full_validation": report, "target_audit": gp.assess(scores),
            "point_target_met": point_target, "support_audit": best_case_support(valid),
            "model_fit_cases": len(fit_rows), "threshold_cases": len(threshold_rows), "validation_cases": len(valid),
            "protocol_sha256": gp.file_hash(output / "protocol.json"), "models_sha256": gp.file_hash(output / "models.json.gz"),
            "fitted_sha256": gp.file_hash(output / "fitted.json"), "thresholds_sha256": gp.file_hash(output / "thresholds.json"),
            "completed_at": gp.now(), "validation_labels_changed": False, "model_refitted_after_threshold": False,
            "llm_weights_updated": False, "live_detector_changed": False, "reserved_test_accessed": False, "scope": PLAN["scope"]})
        return {k: scores[k] for k in ("cases", "tp", "fp", "tn", "fn", "precision", "recall", "specificity")} | {"point_target_met": point_target}
    except Exception as exc:
        gp.write_json(output / "evaluation-failure.json", {"at": gp.now(), "error": f"{type(exc).__name__}: {exc}"})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("prepare", "fit", "threshold", "evaluate"))
    parser.add_argument("--anchor", type=Path, default=ROOT / "training/runs/mac-grouped-precision-v1")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--experimental", action="store_true", required=True)
    args = parser.parse_args()
    actions = {"fit": fit, "threshold": choose_thresholds, "evaluate": evaluate_frozen}
    result = prepare(args.anchor, args.output) if args.stage == "prepare" else actions[args.stage](args.output)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
