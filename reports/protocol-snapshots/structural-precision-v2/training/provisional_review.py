"""Use provisional AI-assisted training reviews without claiming signed human consensus."""

import argparse
import copy
import hashlib
import json
import sys
import warnings
from collections import Counter
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sentinel.modeling.clones import normalized_tokens
from sentinel.modeling.data import strip_comments
from sentinel.modeling.properties import PROPERTIES
from training.binary_mlx import read_development, source_and_target, write_json
from training.frozen_probe import CODE, evaluate, load_protocol, validate_receipt
from training.frozen_probe import PLAN as ORIGINAL_PLAN
from training.local_model import file_hash
from training.precision_target import assess, verify_report

PLAN = {
    "name": "provisional-review-balanced-v1", "seed": 419, "solver": "liblinear", "penalty": "l2",
    "C": 1.0, "tol": 0.0001, "max_iter": 2000, "class_weight": "balanced", "fit_intercept": True,
    "threshold": 0.5, "scikit_learn": "1.7.2", "lexical_max_features": 4096,
    "families": ["frozen_qwen", "lexical_matched", "lexical_full"],
    "arms": ["historical", "provisional"],
    "review_rule": "Only matching definite A/B training decisions become provisional source-assessment labels. "
                   "Disputed, unknown and pending cases stay in the ledger and are omitted from the provisional training loss only.",
    "scope": "User-reported human approval of AI-assisted reviews, written reports pending. "
             "Exploratory development only; not authenticated human sign-off, independent blind consensus, "
             "verified executable labels or an external benchmark. Validation labels and coverage are unchanged.",
    "hyperparameter_search": False, "calibration": False, "base_weights_updated": False,
}
APPROVAL = {
    "status": "user_reported_approval_written_reports_pending", "reported_in_chat_date": "2026-10-23",
    "source": "Current user's instruction to continue using both submitted results",
    "approvers_reported_by_user": ["project professor", "resource person"],
    "reported_statement": "Both said the results are correct and will provide reports after some days; continue work now.",
    "names_or_institutional_ids": None, "written_reports": [], "authenticated_signatures": False,
    "coverage_and_review_method_independently_verified": False,
    "scope": "Record the user's report, not invented reviewer identities, credentials, signatures or blind independence.",
}
IMPLEMENTATIONS = (*CODE, "training/precision_target.py", "training/provisional_review.py")
INPUTS = {"packet": "cases.json", "manifest": "original-manifest.json", "mapping": "admin.json",
          "a": "reviewer-a.json", "b": "reviewer-b.json"}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def reconcile(raws: dict, rows: dict) -> dict:
    documents = {key: json.loads(raw) for key, raw in raws.items()}
    packet, manifest, mapping = (documents[key] for key in ("packet", "manifest", "mapping"))
    if packet["manifest_sha256"] != sha(raws["manifest"]):
        raise ValueError("Review packet differs from its original manifest")
    cases = {case["id"]: case for case in manifest["cases"]}
    blind = {case["review_id"]: case for case in packet["cases"]}
    identities = mapping["case_mapping"]
    expected = {row["id"]: row for row in rows["train"] if row["swc"] == "104"}
    if (len(cases) != len(manifest["cases"]) or len(blind) != len(packet["cases"])
            or len(identities) != len(cases) or set(identities.values()) != cases.keys()
            or set(identities) != blind.keys() or cases.keys() != expected.keys() or not expected):
        raise ValueError("Review must cover exactly the entire selected SWC-104 training pool")
    submissions = {}
    for name in ("a", "b"):
        document = documents[name]
        if document.get("packet_sha256") != sha(raws["packet"]) or document.get("manifest_sha256") != sha(raws["manifest"]):
            raise ValueError("Submission does not match the frozen review packet")
        reviewer = document.get("reviewer", {})
        if reviewer.get("kind") not in {"ai", "human"} or not isinstance(reviewer.get("id"), str) or not reviewer["id"].strip():
            raise ValueError("Preserve an explicitly declared reviewer identity and method")
        entries = document.get("reviews", [])
        index = {row["review_id"]: row for row in entries}
        if len(index) != len(entries) or index.keys() != blind.keys():
            raise ValueError("Each submission must contain every review ID exactly once")
        submissions[name] = index
    if documents["a"]["reviewer"]["id"].strip().casefold() == documents["b"]["reviewer"]["id"].strip().casefold():
        raise ValueError("Two distinctly attributed review observations are required")
    ledger = []
    for review_id, case_id in sorted(identities.items()):
        case, context, row = cases[case_id], blind[review_id], expected[case_id]
        source, target = source_and_target(row)
        source_pin, blind_pin = sha(source.encode()), sha(strip_comments(source).encode())
        if (case.get("provenance", {}).get("role") != "training" or case.get("group") != "development"
                or case.get("target_contract") != row["contract"] or context["target_contract"] != row["contract"]
                or case.get("source_sha256") != source_pin or context["source_sha256"] != source_pin
                or context["blind_source_sha256"] != blind_pin
                or context["line_count"] != len(source.splitlines()) or context.get("context_files") != []
                or case["vulnerability_class"] != f"SWC-104: {PROPERTIES['104']}"
                or context["vulnerability_class"] != case["vulnerability_class"]
                or review_id != "review-" + sha(f"{sha(raws['manifest'])}:{case_id}".encode())[:16]):
            raise ValueError("Review target, source, property, role or opaque identity differs")
        decisions = []
        for name in ("a", "b"):
            entry = submissions[name][review_id]
            decision, lines = entry.get("decision"), entry.get("evidence_lines")
            if (entry.get("source_sha256") != source_pin or decision not in {"vulnerable", "clean", "unknown", "pending"}
                    or not isinstance(lines, list)
                    or any(type(n) is not int or not 1 <= n <= context["line_count"] for n in lines)
                    or decision in {"vulnerable", "clean"} and not lines
                    or decision != "pending" and (not isinstance(entry.get("rationale"), str) or not entry["rationale"].strip())):
                raise ValueError("Invalid decision, source pin, rationale or evidence lines")
            decisions.append(decision)
        agreed = decisions[0] == decisions[1] and decisions[0] in {"vulnerable", "clean"}
        state = "agreed_definite" if agreed else "both_unknown" if decisions == ["unknown", "unknown"] else "unresolved"
        label = decisions[0] == "vulnerable" if agreed else None
        ledger.append({"id": case_id, "review_id": review_id, "swc": "104", "contract": row["contract"],
                       "source_sha256": source_pin, "historical_label": target["vulnerable"],
                       "a_decision": decisions[0], "b_decision": decisions[1], "status": state,
                       "provisional_label": label, "eligible_for_provisional_training": agreed})
    counts = Counter(row["status"] for row in ledger)
    return {"cases": ledger, "coverage": len(ledger), "status_counts": dict(sorted(counts.items())),
            "eligible": sum(r["eligible_for_provisional_training"] for r in ledger),
            "withheld_from_training": sum(not r["eligible_for_provisional_training"] for r in ledger),
            "label_changes_among_agreements": sum(r["eligible_for_provisional_training"] and r["provisional_label"] != r["historical_label"] for r in ledger),
            "declared_reviewers": {name: documents[name]["reviewer"] for name in ("a", "b")},
            "approval_report": APPROVAL, "signed_human_consensus": False,
            "original_dataset_modified": False, "scope": PLAN["scope"]}


def overlay(rows: list[dict], ledger: dict) -> tuple[list[dict], list[int]]:
    index = {case["id"]: case for case in ledger["cases"]}
    if len(index) != len(ledger["cases"]) or not index.keys() <= {r["id"] for r in rows}:
        raise ValueError("Provisional review identities must exist in this training pool")
    selected, indices = [], []
    for i, original in enumerate(rows):
        case = index.get(original["id"])
        source, target = source_and_target(original)
        if case is not None:
            if case["swc"] != target["swc"] or case["source_sha256"] != sha(source.encode()):
                raise ValueError("Provisional labels cannot move across source or property")
            if case["provisional_label"] is None:
                if case["eligible_for_provisional_training"] is not False:
                    raise ValueError("Unknown labels cannot be declared eligible")
                continue
            if type(case["provisional_label"]) is not bool or case["eligible_for_provisional_training"] is not True:
                raise ValueError("Only explicit definite provisional labels can enter training")
            current = copy.deepcopy(original)
            current["messages"][-1]["content"] = json.dumps({"swc": target["swc"], "vulnerable": case["provisional_label"]})
        else:
            current = copy.deepcopy(original)
        selected.append(current)
        indices.append(i)
    return selected, indices


def cohort_counts(matched: dict, full: dict, ledger: dict) -> dict:
    reviewed_matched, _ = overlay(matched["train"], ledger)
    reviewed_full, _ = overlay(full["train"], ledger)
    return {"matched_historical": len(matched["train"]), "matched_provisional": len(reviewed_matched),
            "full_historical": len(full["train"]), "full_provisional": len(reviewed_full),
            "matched_validation": len(matched["valid"]), "full_validation": len(full["valid"])}


def prepare(probe: Path, packet: Path, reviewer_a: Path, reviewer_b: Path, output: Path) -> dict:
    output = output.resolve()
    if output.exists():
        raise FileExistsError("Choose a new directory; preserve earlier review experiments")
    original, rows = load_protocol(probe)
    full, pins = read_development(Path(original["dataset"]))
    if pins != original["input_pins"]:
        raise ValueError("Full dataset differs from the frozen probe")
    if any(output.is_relative_to(p.resolve()) for p in (probe, packet, Path(original["dataset"]), reviewer_a.parent, reviewer_b.parent)):
        raise ValueError("Experiment output must be outside original inputs")
    paths = {"packet": packet / "blind/cases.json", "manifest": packet / "original-manifest.json",
             "mapping": packet / "admin.json", "a": reviewer_a, "b": reviewer_b}
    raws = {name: path.read_bytes() for name, path in paths.items()}
    ledger = reconcile(raws, rows)
    receipt = json.loads((probe / "features.json").read_text())
    validate_receipt(probe, rows, receipt)
    counts = cohort_counts(rows, full, ledger)
    protocol = {"plan": PLAN, "approval_report": APPROVAL, "created_at": datetime.now(UTC).isoformat(),
                "probe": str(probe.resolve()), "dataset": original["dataset"], "input_pins": pins,
                "implementation_sha256": {name: file_hash(ROOT / name) for name in IMPLEMENTATIONS},
                "review_input_sha256": {name: sha(raw) for name, raw in raws.items()},
                "original_review_paths": {name: str(path.resolve()) for name, path in paths.items()},
                "probe_pins": {str((probe / name).resolve()): file_hash(probe / name)
                               for name in ("protocol.json", "features.json", "features.npz", "comparison.json", "classifiers.json")},
                "counts": counts, "reserved_test_accessed": False}
    output.mkdir(parents=True)
    (output / "review-inputs").mkdir()
    for name, raw in raws.items():
        with (output / "review-inputs" / INPUTS[name]).open("xb") as handle:
            handle.write(raw)
    write_json(output / "review-decisions.json", ledger)
    protocol["ledger_sha256"] = file_hash(output / "review-decisions.json")
    write_json(output / "protocol.json", protocol)
    return {"status": "provisional_not_signed_consensus", "reviewed_training_cases": ledger["coverage"],
            "eligible_provisional_cases": ledger["eligible"], "unresolved_cases": ledger["withheld_from_training"], **counts}


def load(output: Path) -> tuple[dict, dict, dict, dict]:
    protocol = json.loads((output / "protocol.json").read_text())
    if protocol.get("plan") != PLAN or protocol.get("approval_report") != APPROVAL or set(protocol.get("implementation_sha256", {})) != set(IMPLEMENTATIONS):
        raise ValueError("Provisional experiment protocol or approval provenance differs")
    for name, pin in protocol["implementation_sha256"].items():
        if file_hash(ROOT / name) != pin:
            raise ValueError("Experiment implementation changed")
    for name, pin in protocol["probe_pins"].items():
        if file_hash(Path(name)) != pin:
            raise ValueError("Frozen probe artifacts changed")
    original, rows = load_protocol(Path(protocol["probe"]))
    full, pins = read_development(Path(protocol["dataset"]))
    if pins != protocol["input_pins"] or pins != original["input_pins"]:
        raise ValueError("Dataset changed after preparation")
    raws = {name: (output / "review-inputs" / filename).read_bytes() for name, filename in INPUTS.items()}
    if {name: sha(raw) for name, raw in raws.items()} != protocol["review_input_sha256"]:
        raise ValueError("Preserved review inputs changed")
    ledger = reconcile(raws, rows)
    if file_hash(output / "review-decisions.json") != protocol["ledger_sha256"] or ledger != json.loads((output / "review-decisions.json").read_text()):
        raise ValueError("Provisional decision ledger differs from preserved evidence")
    if protocol["counts"] != cohort_counts(rows, full, ledger):
        raise ValueError("Training or validation coverage differs from the prepared protocol")
    return protocol, rows, full, ledger


def fit_heads(training: list[dict], valid: list[dict], train_features=None, valid_features=None) -> tuple[dict, dict]:
    from sklearn.exceptions import ConvergenceWarning
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import normalize

    parameters, margins = {}, {}
    for swc in PROPERTIES:
        ti = [i for i, row in enumerate(training) if row["swc"] == swc]
        vi = [i for i, row in enumerate(valid) if row["swc"] == swc]
        labels = [int(source_and_target(training[i])[1]["vulnerable"]) for i in ti]
        if set(labels) != {0, 1} or not vi:
            raise ValueError("Both training labels and validation coverage are required per property")
        if train_features is not None:
            x_train, x_valid = normalize(train_features[ti], norm="l2"), normalize(valid_features[vi], norm="l2")
            preprocessing = {"normalization": "L2 per row; no validation-fitted statistics"}
        else:
            vectorizer = TfidfVectorizer(analyzer=normalized_tokens, max_features=PLAN["lexical_max_features"])
            x_train = vectorizer.fit_transform([source_and_target(training[i])[0] for i in ti])
            x_valid = vectorizer.transform([source_and_target(valid[i])[0] for i in vi])
            preprocessing = {"vocabulary": {term: int(index) for term, index in vectorizer.vocabulary_.items()},
                             "idf": vectorizer.idf_.tolist(), "normalization": "Training-only L2 TF-IDF"}
        classifier = LogisticRegression(C=PLAN["C"], solver=PLAN["solver"], penalty=PLAN["penalty"],
            tol=PLAN["tol"], max_iter=PLAN["max_iter"], random_state=PLAN["seed"],
            fit_intercept=PLAN["fit_intercept"], class_weight=PLAN["class_weight"])
        with warnings.catch_warnings():
            warnings.simplefilter("error", ConvergenceWarning)
            classifier.fit(x_train, labels)
        if classifier.classes_.tolist() != [0, 1]:
            raise ValueError("Unexpected classifier label mapping")
        values = classifier.decision_function(x_valid).tolist()
        margins.update({valid[i]["id"]: value for i, value in zip(vi, values, strict=True)})
        counts = Counter(labels)
        parameters[swc] = {"coefficients": classifier.coef_.tolist(), "intercept": classifier.intercept_.tolist(),
                           "classes": [0, 1], "iterations": classifier.n_iter_.tolist(), "preprocessing": preprocessing,
                           "training_counts": {"negative": counts[0], "positive": counts[1]},
                           "balanced_class_weights": {str(label): len(labels) / (2 * counts[label]) for label in (0, 1)}}
    report = evaluate(valid, margins)
    verify_report(report, valid)
    report["target_audit"] = assess(report["scores"])
    return report, parameters


def score(output: Path) -> dict:
    if any((output / name).exists() for name in ("classifiers.json", "comparison.json", "execution.json")):
        raise FileExistsError("Preserve earlier attempts; choose a new experiment directory")
    protocol, matched, full, ledger = load(output)
    if version("scikit-learn") != PLAN["scikit_learn"]:
        raise ValueError("Pinned scikit-learn required")
    import numpy as np

    probe = Path(protocol["probe"])
    receipt = json.loads((probe / "features.json").read_text())
    validate_receipt(probe, matched, receipt)
    with np.load(probe / "features.npz", allow_pickle=False) as archive:
        if set(archive.files) != {"train", "valid"}:
            raise ValueError("Unexpected feature archive contents")
        matrices = {split: archive[split] for split in matched}
    for split, matrix in matrices.items():
        if (matrix.shape != (len(matched[split]), ORIGINAL_PLAN["hidden_size"]) or matrix.dtype != np.float32
                or not np.isfinite(matrix).all() or np.any(np.linalg.norm(matrix, axis=1) == 0)):
            raise ValueError("Invalid cached frozen-model features")
    results, parameters = {}, {}
    execution = {"status": "started", "started_at": datetime.now(UTC).isoformat(), "completed_arms": []}
    write_json(output / "execution.json", execution)
    try:
        for family in PLAN["families"]:
            pool = full if family == "lexical_full" else matched
            results[family], parameters[family] = {}, {}
            for arm in PLAN["arms"]:
                training, indices = (overlay(pool["train"], ledger) if arm == "provisional"
                                     else (copy.deepcopy(pool["train"]), list(range(len(pool["train"])))))
                features = matrices["train"][indices] if family == "frozen_qwen" else None
                valid_features = matrices["valid"] if family == "frozen_qwen" else None
                report, heads = fit_heads(training, pool["valid"], features, valid_features)
                report["training_cases"] = len(training)
                report["validation_cases"] = len(pool["valid"])
                if family == "lexical_full":
                    predictions = {r["id"]: r["classifier_margin"] for r in report["predictions"]}
                    report["original_54_subset"] = evaluate(matched["valid"], {r["id"]: predictions[r["id"]] for r in matched["valid"]})
                results[family][arm], parameters[family][arm] = report, heads
                execution["completed_arms"].append(f"{family}:{arm}")
                scores = report["scores"]
                print(f"{family}/{arm}: train={len(training)}, validation={len(pool['valid'])}, "
                      f"precision={scores['precision']}, recall={scores['recall']}, specificity={scores['specificity']}", flush=True)
        comparison = {"plan": PLAN, "approval_report": APPROVAL, "review_coverage": ledger["coverage"],
                      "agreed_definite_training_cases": ledger["eligible"], "unresolved_training_cases": ledger["withheld_from_training"],
                      "results": results, "protocol_sha256": file_hash(output / "protocol.json"),
                      "ledger_sha256": file_hash(output / "review-decisions.json"),
                      "packages": {name: version(name) for name in ("numpy", "scipy", "scikit-learn")},
                      "signed_human_consensus": False, "original_dataset_modified": False,
                      "validation_labels_changed": False, "base_weights_updated": False,
                      "reserved_test_accessed": False, "independent_99_percent_claim_supported": False,
                      "scope": PLAN["scope"] + " All six arms are retained; no winning model is selected. "
                               "Unknown training assessments are withheld, never relabelled clean. "
                               "The full lexical family has more training/evaluation data and is not an LLM result."}
        write_json(output / "classifiers.json", parameters)
        comparison["classifiers_sha256"] = file_hash(output / "classifiers.json")
        write_json(output / "comparison.json", comparison)
        execution.update(status="completed", finished_at=datetime.now(UTC).isoformat())
    except BaseException as exc:
        execution.update(status="interrupted" if isinstance(exc, KeyboardInterrupt) else "failed", error=f"{type(exc).__name__}: {exc}")
        raise
    finally:
        (output / "execution.json").write_text(json.dumps(execution, indent=2) + "\n", encoding="utf-8")
    return {family: {arm: {k: r["scores"][k] for k in ("precision", "recall", "specificity")}
                     for arm, r in values.items()} for family, values in results.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "score"))
    parser.add_argument("--probe", type=Path, default=ROOT / "training/runs/mac-frozen-probe-v1")
    parser.add_argument("--packet", type=Path, default=ROOT / "reports/label-review/binary-v1/training")
    parser.add_argument("--reviewer-a", type=Path, default=ROOT / "reports/label-review/submissions/ai-reviewer-a-109f1e1622ed/reviewer-a-full-review.json")
    parser.add_argument("--reviewer-b", type=Path, default=ROOT / "reports/label-review/submissions/reviewer-b-screenshots-2026-10-23/reviewer-b-full-existing.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--experimental", action="store_true")
    args = parser.parse_args()
    if not args.experimental:
        raise SystemExit("Provisional review use requires --experimental; written human reports are pending")
    result = prepare(args.probe, args.packet, args.reviewer_a, args.reviewer_b, args.output) if args.action == "prepare" else score(args.output)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
