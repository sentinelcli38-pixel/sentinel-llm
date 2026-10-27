"""Contract-scoped syntax features and training-only selection; not a qualified detector."""

import argparse
import json
import math
import shutil
import subprocess
import sys
import warnings
from collections import Counter
from importlib.metadata import version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from training import grouped_precision as gp

PARSER_INTEGRITY = "sha512-rbu0bzwNvMcwAjH86hiEAcOeRI2EeK8zCkHDrFykh/Al8mvJeFmjy3UrE7GYQjNwOgbGUUtCn5/k8CB8zIu7QA=="
PLAN = {
    "name": "contract-structural-precision-v1", "seed": 617, "folds": 3, "scikit_learn": "1.7.2",
    "parser": "@solidity-parser/parser", "parser_version": "0.20.2", "parser_integrity": PARSER_INTEGRITY,
    "representations": ["ast_tree", "scoped_tokens", "ast_and_tokens"], "C": [0.1, 1.0, 10.0],
    "class_weight": [None, "balanced"], "tree_min_leaf": [1, 3, 8], "tree_count": 128,
    "tree_max_depth": 12, "tree_max_features": 1.0, "tree_jobs": 1,
    "linear_solver": "liblinear", "linear_max_iter": 5000, "linear_tol": 0.0001,
    "target_precision": 0.99, "minimum_recall": 0.8, "minimum_specificity": 0.8,
    "selection": gp.PLAN["selection"],
    "scope": "Contract-targeted syntax experiment, not semantic execution, dataflow proof, calibrated probability, "
             "LLM tuning, nested CV or independent testing. Same historically inspected development validation. "
             "Original labels and all evaluation cases retained; no deployment or reserved test access.",
    "fallback": "Strict parse/target failure remains explicit; use whole-source lexical fallback and status features. "
                "Never remove the case or automatically call it clean.",
    "inheritance": "Aggregate syntactic declarations from named target and unique in-file base closure, in separate "
                   "target/base channels. Not C3 dispatch resolution or interprocedural reachability. "
                   "Record unresolved bases/imports and modifier ambiguity; never execute imported code.",
    "feature_scaling": "Tree: raw numeric AST counts. Linear: log1p AST counts, row L2 normalization, plus "
                       "training-fitted normalized-token 1-3 gram TF-IDF, then row L2 normalization. "
                       "Fit each vocabulary inside each fitting fold. Unknown held features ignored.",
    "score": "Use model positive-class scores for training-only thresholds; save shifted score minus threshold "
             "as a classifier margin. Neither these scores nor their sigmoid are calibrated vulnerability probabilities.",
    "convergence_warning": "Abort, retain failure receipt and completed properties; no silent candidate removal.",
}
IMPLEMENTATIONS = (*gp.IMPLEMENTATIONS, "training/structural_precision.py", "training/ast_features/extract.cjs",
                   "training/ast_features/package.json", "training/ast_features/package-lock.json",
                   "training/requirements-probe.txt")


def catalog():
    trees = [{"id": f"ast_tree-leaf{leaf}-{'balanced' if weight else 'unweighted'}", "representation": "ast_tree",
              "min_samples_leaf": leaf, "class_weight": weight}
             for leaf in PLAN["tree_min_leaf"] for weight in PLAN["class_weight"]]
    linear = [{"id": f"{rep}-c{c:g}-{'balanced' if weight else 'unweighted'}", "representation": rep,
               "C": c, "class_weight": weight}
              for rep in ("scoped_tokens", "ast_and_tokens") for c in PLAN["C"] for weight in PLAN["class_weight"]]
    return trees + linear


def runtime():
    node = shutil.which("node")
    if not node:
        raise ValueError("Node.js and the isolated pinned Solidity parser are required")
    directory = ROOT / "training/ast_features/node_modules/@solidity-parser/parser"
    package = json.loads((directory / "package.json").read_text())
    lock = json.loads((ROOT / "training/ast_features/package-lock.json").read_text())
    pinned = lock["packages"]["node_modules/@solidity-parser/parser"]
    if package["version"] != PLAN["parser_version"] or pinned["version"] != PLAN["parser_version"] or pinned["integrity"] != PARSER_INTEGRITY:
        raise ValueError("Parser version or lock integrity differs")
    bundle = (directory / package["main"]).resolve()
    if not bundle.is_relative_to(directory.resolve()) or package.get("dependencies"):
        raise ValueError("Expected the standalone pinned parser bundle")
    return {"node": str(Path(node).resolve()), "node_version": subprocess.check_output([node, "--version"], text=True).strip(),
            "node_sha256": gp.file_hash(Path(node)), "parser_bundle_sha256": gp.file_hash(bundle),
            "parser_package_sha256": gp.file_hash(directory / "package.json")}


def prepare(anchor: Path, output: Path):
    if output.exists():
        raise FileExistsError("Choose a fresh directory; preserve all earlier attempts")
    original, rows = gp.load_training(anchor)
    if any(output.resolve().is_relative_to(p.resolve()) for p in (anchor, Path(original["input_pins"]["path"]), Path(original["review"]))):
        raise ValueError("Do not write inside original inputs")
    if version("scikit-learn") != PLAN["scikit_learn"]:
        raise ValueError("Install the pinned optional probe dependencies")
    protocol = {"plan": PLAN, "catalog": catalog(), "created_at": gp.now(), "anchor": str(anchor.resolve()),
                "anchor_protocol_sha256": gp.file_hash(anchor / "protocol.json"), "input_pins": original["input_pins"],
                "training_ids": [r["id"] for r in rows], "folds": original["folds"],
                "approval_report": original["approval_report"], "withheld_training_cases": original["withheld_training_cases"],
                "implementation_sha256": {name: gp.file_hash(ROOT / name) for name in IMPLEMENTATIONS},
                "runtime": runtime(), "validation_accessed_during_selection": False, "reserved_test_accessed": False}
    output.mkdir(parents=True)
    gp.write_json(output / "protocol.json", protocol)
    return {"training_cases": len(rows), "candidates_per_property": len(catalog()), "validation_accessed": False}


def load_training(output: Path):
    protocol = json.loads((output / "protocol.json").read_text())
    if protocol["plan"] != PLAN or protocol["catalog"] != catalog() or set(protocol["implementation_sha256"]) != set(IMPLEMENTATIONS):
        raise ValueError("Structural protocol differs")
    for name, pin in protocol["implementation_sha256"].items():
        if gp.file_hash(ROOT / name) != pin:
            raise ValueError("Structural implementation changed")
    anchor = Path(protocol["anchor"])
    if gp.file_hash(anchor / "protocol.json") != protocol["anchor_protocol_sha256"]:
        raise ValueError("Training-only anchor changed")
    original, rows = gp.load_training(anchor)
    if (protocol["training_ids"] != [r["id"] for r in rows] or protocol["input_pins"] != original["input_pins"]
            or protocol["folds"] != original["folds"] or protocol["runtime"] != runtime()
            or protocol["approval_report"] != original["approval_report"]
            or protocol["withheld_training_cases"] != original["withheld_training_cases"]):
        raise ValueError("Training identities, folds, runtime or review provenance differ")
    return protocol, rows


def validate_features(record, expected):
    if (record["key"] != expected["key"] or record["source_sha256"] != expected["source_sha256"]
            or record["contract"] != expected["contract"]
            or record["status"] not in {"parsed", "parse_error", "target_missing", "target_ambiguous"}
            or not isinstance(record["scoped_source"], str) or not record["scoped_source"]
            or not isinstance(record["features"], dict) or not record["features"]
            or any(not isinstance(k, str) or not k or type(v) not in (int, float) or not math.isfinite(v) or v < 0
                   for k, v in record["features"].items())
            or record["features"].get(f"extraction.{record['status']}") != 1):
        raise ValueError("Malformed, nonfinite or misattributed source features")
    if record["status"] != "parsed" and record["scoped_source"] != expected["source"]:
        raise ValueError("Extraction failure must preserve the declared whole-source fallback")


def extract(rows):
    entries, row_keys = {}, {}
    if not rows or len({r["id"] for r in rows}) != len(rows):
        raise ValueError("A complete unique cohort is required")
    for row in rows:
        source, _ = gp.source_and_target(row)
        key = gp.sha(f"{row['source_hash']}:{row['contract']}".encode())
        entries[key] = {"key": key, "source": source, "source_sha256": row["source_hash"], "contract": row["contract"]}
        row_keys[row["id"]] = key
    payload = sorted(entries.values(), key=lambda e: (e["source_sha256"], e["contract"]))
    completed = subprocess.run([runtime()["node"], "--max-old-space-size=2048", str(ROOT / "training/ast_features/extract.cjs")],
                               input=json.dumps(payload), text=True, stdout=subprocess.PIPE, check=True, timeout=900)
    result = json.loads(completed.stdout)
    if len(result) != len(entries) or {r["key"] for r in result} != entries.keys():
        raise ValueError("Parser worker must return every source/target exactly once")
    for record in result:
        validate_features(record, entries[record["key"]])
    index = {r["key"]: r for r in result}
    return {"records": index, "row_keys": row_keys, "unique_targets": len(entries),
            "status_counts": dict(Counter(index[key]["status"] for key in row_keys.values()))}


def records_for(rows, cache):
    if set(cache["row_keys"]) != {r["id"] for r in rows}:
        raise ValueError("Feature cache cohort differs")
    result = []
    for row in rows:
        source, _ = gp.source_and_target(row)
        key = gp.sha(f"{row['source_hash']}:{row['contract']}".encode())
        if cache["row_keys"][row["id"]] != key:
            raise ValueError("Feature cache identity moved")
        record = cache["records"][key]
        validate_features(record, {"key": key, "source_sha256": row["source_hash"], "source": source, "contract": row["contract"]})
        result.append(record)
    return result


def fit_features(records, representation):
    from sklearn.feature_extraction import DictVectorizer

    if representation not in PLAN["representations"]:
        raise ValueError("Unknown structural representation")
    preprocessing = {"representation": representation}
    if representation != "scoped_tokens":
        vectorizer = DictVectorizer()
        vectorizer.fit([r["features"] for r in records])
        preprocessing["ast_vocabulary"] = vectorizer.vocabulary_
        preprocessing["ast_feature_names"] = vectorizer.feature_names_
    if representation != "ast_tree":
        vectorizer = gp.vectorizer("tokens_1_3")
        vectorizer.fit([r["scoped_source"] for r in records])
        preprocessing["token_vocabulary"] = {k: int(v) for k, v in vectorizer.vocabulary_.items()}
        preprocessing["idf"] = vectorizer.idf_.tolist()
    return transform_features(records, preprocessing), preprocessing


def transform_features(records, preprocessing):
    import numpy as np
    from scipy.sparse import hstack
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.preprocessing import normalize

    representation = preprocessing["representation"]
    if representation not in PLAN["representations"]:
        raise ValueError("Unknown structural representation")
    parts = []
    if representation != "scoped_tokens":
        vectorizer = DictVectorizer()
        vectorizer.vocabulary_, vectorizer.feature_names_ = preprocessing["ast_vocabulary"], preprocessing["ast_feature_names"]
        x = vectorizer.transform([r["features"] for r in records])
        if representation == "ast_tree":
            result = x.toarray().astype(np.float32)
            if not np.isfinite(result).all():
                raise ValueError("Nonfinite structural matrix")
            return result
        x.data = np.log1p(x.data)
        parts.append(normalize(x, norm="l2"))
    if representation != "ast_tree":
        vectorizer = gp.vectorizer("tokens_1_3", preprocessing["token_vocabulary"], preprocessing["idf"])
        parts.append(vectorizer.transform([r["scoped_source"] for r in records]))
    result = normalize(hstack(parts, format="csr"), norm="l2")
    if not np.isfinite(result.data).all():
        raise ValueError("Nonfinite combined matrix")
    return result


def classifier(candidate):
    if candidate["representation"] == "ast_tree":
        from sklearn.ensemble import ExtraTreesClassifier

        return ExtraTreesClassifier(n_estimators=PLAN["tree_count"], max_depth=PLAN["tree_max_depth"],
            min_samples_leaf=candidate["min_samples_leaf"], max_features=PLAN["tree_max_features"],
            class_weight=candidate["class_weight"], n_jobs=PLAN["tree_jobs"], random_state=PLAN["seed"])
    from sklearn.linear_model import LogisticRegression

    return LogisticRegression(C=candidate["C"], class_weight=candidate["class_weight"], solver=PLAN["linear_solver"],
        max_iter=PLAN["linear_max_iter"], tol=PLAN["linear_tol"], random_state=PLAN["seed"])


def export_model(candidate, selected, preprocessing, model):
    result = {"candidate": candidate, "threshold": selected["threshold"], "preprocessing": preprocessing,
              "classes": model.classes_.tolist(), "score_is_calibrated_probability": False}
    if candidate["representation"] == "ast_tree":
        result["trees"] = []
        for estimator in model.estimators_:
            tree = estimator.tree_
            values = tree.value[:, 0, :]
            result["trees"].append({"left": tree.children_left.tolist(), "right": tree.children_right.tolist(),
                "feature": tree.feature.tolist(), "threshold": tree.threshold.tolist(),
                "positive_fraction": (values[:, 1] / values.sum(axis=1)).tolist()})
    else:
        result.update(coefficient=model.coef_[0].tolist(), intercept=float(model.intercept_[0]))
    return result


def replay(model, records):
    import numpy as np

    if model["classes"] != [0, 1] or not math.isfinite(model["threshold"]):
        raise ValueError("Invalid classifier orientation or threshold")
    x = transform_features(records, model["preprocessing"])
    if model["candidate"]["representation"] == "ast_tree":
        if not model["trees"]:
            raise ValueError("Missing JSON tree ensemble")
        scores = np.zeros(len(records))
        for tree in model["trees"]:
            left, right, feature = (np.asarray(tree[name], dtype=np.int64) for name in ("left", "right", "feature"))
            thresholds, fractions = (np.asarray(tree[name], dtype=np.float64) for name in ("threshold", "positive_fraction"))
            n = len(left)
            internal = left != -1
            if (not n or any(len(v) != n for v in (right, feature, thresholds, fractions))
                    or not np.isfinite(thresholds).all() or not np.isfinite(fractions).all()
                    or np.any((fractions < 0) | (fractions > 1))
                    or np.any((left[internal] < 0) | (left[internal] >= n) | (right[internal] < 0) | (right[internal] >= n))
                    or np.any((feature[internal] < 0) | (feature[internal] >= x.shape[1]))
                    or np.any(right[~internal] != -1)):
                raise ValueError("Malformed JSON tree")
            positions = np.zeros(len(records), dtype=np.int64)
            for _ in range(n + 1):
                active = np.flatnonzero(left[positions] != -1)
                if not len(active):
                    break
                nodes = positions[active]
                positions[active] = np.where(x[active, feature[nodes]] <= thresholds[nodes], left[nodes], right[nodes])
            else:
                raise ValueError("JSON tree traversal cycle")
            scores += fractions[positions]
        scores /= len(model["trees"])
    else:
        coefficients = np.asarray(model["coefficient"], dtype=np.float64)
        if len(coefficients) != x.shape[1] or not np.isfinite(coefficients).all() or not math.isfinite(model["intercept"]):
            raise ValueError("Malformed JSON linear head")
        raw = (x @ coefficients + model["intercept"]).tolist()
        scores = np.asarray([gp.probability([0.0, value]) for value in raw])
    if not np.isfinite(scores).all() or np.any((scores < 0) | (scores > 1)):
        raise ValueError("Nonfinite or out-of-range model score")
    return scores.tolist()


def fit(output: Path):
    if any((output / name).exists() for name in ("fit-started.json", "models.json", "selection.json", "fit.json")):
        raise FileExistsError("Fit already attempted; preserve all outcomes")
    protocol, rows = load_training(output)
    if version("scikit-learn") != PLAN["scikit_learn"]:
        raise ValueError("Wrong optional scikit-learn version")
    import numpy as np
    from sklearn.exceptions import ConvergenceWarning

    gp.write_json(output / "fit-started.json", {"started_at": gp.now(), "protocol_sha256": gp.file_hash(output / "protocol.json")})
    models, selected = {}, {}
    try:
        cache = extract(rows)
        gp.write_json(output / "training-features.json", cache)
        print(f"Training extraction: {cache['unique_targets']} targets; {cache['status_counts']}", flush=True)
        records = records_for(rows, cache)
        with warnings.catch_warnings():
            warnings.simplefilter("error", ConvergenceWarning)
            for swc in gp.PROPERTIES:
                indices = [i for i, row in enumerate(rows) if row["swc"] == swc]
                subset, inputs = [rows[i] for i in indices], [records[i] for i in indices]
                labels = [gp.source_and_target(r)[1]["vulnerable"] for r in subset]
                folds = np.asarray([protocol["folds"][r["id"]] for r in subset])
                candidates = [{**c, "margins": [None] * len(subset)} for c in catalog()]
                for representation in PLAN["representations"]:
                    for fold in range(PLAN["folds"]):
                        ti, vi = np.flatnonzero(folds != fold), np.flatnonzero(folds == fold)
                        x_train, preprocessing = fit_features([inputs[i] for i in ti], representation)
                        x_held = transform_features([inputs[i] for i in vi], preprocessing)
                        for candidate in candidates:
                            if candidate["representation"] != representation:
                                continue
                            model = classifier(candidate).fit(x_train, [int(labels[i]) for i in ti])
                            for i, score in zip(vi, model.predict_proba(x_held)[:, 1].tolist(), strict=True):
                                if candidate["margins"][i] is not None:
                                    raise ValueError("Duplicate OOF training assessment")
                                candidate["margins"][i] = score
                        print(f"SWC-{swc} {representation} fold {fold + 1}/3 completed", flush=True)
                for candidate in candidates:
                    candidate["selection"] = gp.choose_threshold(labels, candidate["margins"])
                selected[swc] = gp.select_candidate(candidates)
                gp.write_json(output / f"oof-{swc}.json", {"ids": [r["id"] for r in subset], "labels": labels, "candidates": candidates})
                chosen = next(c for c in catalog() if c["id"] == selected[swc]["candidate"])
                x_train, preprocessing = fit_features(inputs, chosen["representation"])
                fitted = classifier(chosen).fit(x_train, [int(label) for label in labels])
                model = export_model(chosen, selected[swc], preprocessing, fitted)
                if not np.allclose(replay(model, inputs), fitted.predict_proba(x_train)[:, 1], atol=1e-10, rtol=1e-10):
                    raise ValueError("JSON model does not reproduce fitted predictions")
                models[swc] = model
                print(f"SWC-{swc}: {json.dumps(selected[swc])}", flush=True)
        gp.write_json(output / "models.json", models)
        gp.write_json(output / "selection.json", {"selected": selected, "selection_data": "training-only pooled OOF",
            "scope": PLAN["scope"], "validation_accessed": False,
            "point_targets_met_for_every_property": all(s["point_target_feasible"] for s in selected.values())})
        artifacts = ["models.json", "selection.json", "training-features.json", *(f"oof-{swc}.json" for swc in gp.PROPERTIES)]
        gp.write_json(output / "fit.json", {"status": "completed", "completed_at": gp.now(),
            "protocol_sha256": gp.file_hash(output / "protocol.json"),
            "artifact_sha256": {name: gp.file_hash(output / name) for name in artifacts},
            "runtime_versions": {name: version(name) for name in ("scikit-learn", "numpy", "scipy")},
            "validation_accessed": False, "reserved_test_accessed": False})
        return selected
    except Exception as exc:
        gp.write_json(output / "fit-failure.json", {"status": "failed", "at": gp.now(),
            "error": f"{type(exc).__name__}: {exc}", "completed_properties": list(models), "validation_accessed": False})
        raise


def evaluate_frozen(output: Path):
    if any((output / name).exists() for name in ("evaluation-started.json", "comparison.json")):
        raise FileExistsError("Evaluation already attempted; do not tune or overwrite it")
    protocol, training = load_training(output)
    receipt = json.loads((output / "fit.json").read_text())
    required = {"models.json", "selection.json", "training-features.json", *(f"oof-{swc}.json" for swc in gp.PROPERTIES)}
    if (receipt["status"] != "completed" or receipt["validation_accessed"] is not False
            or receipt["protocol_sha256"] != gp.file_hash(output / "protocol.json") or set(receipt["artifact_sha256"]) != required):
        raise ValueError("Completed frozen training-only fit required")
    for name, pin in receipt["artifact_sha256"].items():
        if gp.file_hash(output / name) != pin:
            raise ValueError("Frozen classifier, features or selection evidence changed")
    if any(version(name) != pin for name, pin in receipt["runtime_versions"].items()):
        raise ValueError("Evaluation runtime differs")
    models, selection = (json.loads((output / name).read_text()) for name in ("models.json", "selection.json"))
    if models.keys() != gp.PROPERTIES.keys() or selection["selected"].keys() != gp.PROPERTIES.keys():
        raise ValueError("All four properties required")
    for swc, model in models.items():
        chosen = selection["selected"][swc]
        if model["candidate"]["id"] != chosen["candidate"] or model["threshold"] != chosen["threshold"]:
            raise ValueError("Selected model or threshold differs")
    gp.write_json(output / "evaluation-started.json", {"started_at": gp.now(), "fit_sha256": gp.file_hash(output / "fit.json")})
    try:
        full, pins = gp.read_development(Path(protocol["input_pins"]["path"]))
        if pins != protocol["input_pins"]:
            raise ValueError("Evaluation input pins changed")
        valid = full["valid"]
        cache = extract(valid)
        gp.write_json(output / "validation-features.json", cache)
        records = records_for(valid, cache)
        margins = {}
        for swc, model in models.items():
            indices = [i for i, row in enumerate(valid) if row["swc"] == swc]
            if not indices:
                raise ValueError("Missing evaluation property")
            scores = replay(model, [records[i] for i in indices])
            margins.update({valid[i]["id"]: score - model["threshold"] for i, score in zip(indices, scores, strict=True)})
        report = gp.evaluate(valid, margins)
        gp.verify_report(report, valid)
        scores = report["scores"]
        point = all(s["precision"] is not None and s["precision"] >= PLAN["target_precision"]
                    and s["recall"] >= PLAN["minimum_recall"] and s["specificity"] >= PLAN["minimum_specificity"]
                    for s in (scores, *scores["per_swc"].values()))
        gp.write_json(output / "comparison.json", {"full_validation": report, "target_audit": gp.assess(scores),
            "point_target_met": point, "selection": selection, "training_cases": len(training), "validation_cases": len(valid),
            "feature_status_counts": cache["status_counts"], "validation_features_sha256": gp.file_hash(output / "validation-features.json"),
            "protocol_sha256": gp.file_hash(output / "protocol.json"), "fit_sha256": gp.file_hash(output / "fit.json"),
            "completed_at": gp.now(), "validation_labels_changed": False, "llm_weights_updated": False,
            "live_detector_changed": False, "reserved_test_accessed": False, "scope": PLAN["scope"]})
        return {"cases": len(valid), "tp": scores["tp"], "fp": scores["fp"], "tn": scores["tn"], "fn": scores["fn"],
                "precision": scores["precision"], "recall": scores["recall"], "specificity": scores["specificity"],
                "point_target_met": point, "feature_status_counts": cache["status_counts"]}
    except Exception as exc:
        gp.write_json(output / "evaluation-failure.json", {"at": gp.now(), "error": f"{type(exc).__name__}: {exc}"})
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("prepare", "fit", "evaluate"))
    parser.add_argument("--anchor", type=Path, default=ROOT / "training/runs/mac-grouped-precision-v1")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--experimental", action="store_true", required=True)
    args = parser.parse_args()
    result = prepare(args.anchor, args.output) if args.stage == "prepare" else (
        fit(args.output) if args.stage == "fit" else evaluate_frozen(args.output))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
