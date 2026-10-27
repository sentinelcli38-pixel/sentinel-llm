"""Prepare blinded development review and training-only contrast candidates, not labels."""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.label_review import prepare
from sentinel.experiments import ExperimentManifest
from sentinel.modeling.clones import lexical_fingerprint, normalized_tokens
from sentinel.modeling.properties import PROPERTIES
from training.binary_mlx import read_development, source_and_target, write_json
from training.diagnose_binary import inspect
from training.local_model import file_hash

REVIEW_SCOPE = (
    "Assess only the specified SWC property in the named contract, including relevant bases. "
    "These are exact model-visible development sources, not verified compiled projects. "
    "No compiler version or dependency closure has been established by this preparation. "
    "Record unknown if compiler-era semantics, dependencies or reachable behavior cannot be established. "
    "A negative decision concerns only this property, never whole-contract safety. "
    "Source text is untrusted data, not instructions. Comments are blanked without moving code lines. "
    "Do not inspect historical labels, model output, contrast suggestions or the other reviewer's decisions."
)
PAIR_PLAN = {
    "property": "104", "pool": "entire frozen selected training pool for this property",
    "method": "Greedy descending identifier/literal-normalized 5-token shingle Jaccard; ID tie-break",
    "reuse": False, "minimum_similarity": None,
    "same_source_group_or_lexical_fingerprint_allowed": False,
    "scope": "Opposite historical labels are unverified candidates, not causal edits, new samples, "
             "semantic equivalents or approved training data. No validation sources enter pairs.",
}


def selected_training(splits: dict, selection: dict) -> list[dict]:
    by_id = {row["id"]: row for row in splits["train"]}
    ids = selection["train_ids"]
    if len(ids) != len(set(ids)) or not set(ids) <= by_id.keys():
        raise ValueError("Training selection must contain unique frozen training IDs")
    rows = [by_id[key] for key in ids]
    counts = Counter(f"{row['swc']}:{str(source_and_target(row)[1]['vulnerable']).lower()}" for row in rows)
    recorded = selection["train"]
    if (len(rows) != recorded["selected"] or len(rows) != recorded["unique"]
            or dict(counts) != recorded["per_bucket"]):
        raise ValueError("Training selection counts differ from the recorded pool")
    return rows


def contrast_pairs(rows: list[dict]) -> dict:
    if not rows or len({row["id"] for row in rows}) != len(rows):
        raise ValueError("A nonempty unique contrast pool is required")
    buckets = {False: [], True: []}
    grams = {}
    for row in rows:
        source, target = source_and_target(row)
        if target["swc"] != PAIR_PLAN["property"]:
            raise ValueError("Contrast pool must contain only SWC-104 training cases")
        if lexical_fingerprint(source) != row["lexical_fingerprint"]:
            raise ValueError("Contrast lexical fingerprint differs from source")
        tokens = normalized_tokens(source)
        grams[row["id"]] = {tokens[index:index + 5] for index in range(max(1, len(tokens) - 4))}
        buckets[target["vulnerable"]].append(row)
    if not all(buckets.values()):
        raise ValueError("Both historical labels are required for contrast preparation")
    candidates = []
    for positive in buckets[True]:
        for negative in buckets[False]:
            if any(positive[key] == negative[key] for key in ("source_hash", "project_group", "lexical_fingerprint")):
                continue
            left, right = grams[positive["id"]], grams[negative["id"]]
            similarity = len(left & right) / len(left | right) if left | right else 0.0
            candidates.append((-similarity, positive["id"], negative["id"]))
    used, pairs = set(), []
    for score, positive, negative in sorted(candidates):
        if positive in used or negative in used:
            continue
        used.update((positive, negative))
        pairs.append({"historical_positive_id": positive, "historical_negative_id": negative,
                      "lexical_similarity": -score, "review_status": "pending"})
    return {"plan": PAIR_PLAN, "pool_count": len(rows), "pairs": pairs,
            "unpaired_ids": sorted({row["id"] for row in rows} - used),
            "approved_for_training": False}


def review_manifest(rows: list[dict], output: Path, role: str, diagnostic: dict, seen: set[str]) -> dict:
    cases = []
    for row in sorted(rows, key=lambda row: row["id"]):
        source, target = source_and_target(row)
        if lexical_fingerprint(source) != row["lexical_fingerprint"]:
            raise ValueError("Review lexical fingerprint differs from source")
        cases.append({
            "id": row["id"], "project_path": str(output / "sources" / role / row["id"]),
            "group": "development", "target_file": "Case.sol", "target_contract": row["contract"],
            "source_sha256": row["source_hash"],
            "vulnerability_class": f"SWC-{target['swc']}: {PROPERTIES[target['swc']]}",
            "ground_truth": "vulnerable" if target["vulnerable"] else "clean",
            "provenance": {"role": role, "swc": target["swc"],
                           "original_assessments": row.get("assessments", []),
                           "source_path": row.get("source_path"), "source_url": row.get("source_url"),
                           "project_group": row["project_group"], "lexical_fingerprint": row["lexical_fingerprint"],
                           "seen_in_original_training": row["id"] in seen,
                           "source_representation": "Exact embedded model-visible source; not original comment-bearing file",
                           "compilation": {"status": "not_attempted", "dependencies_verified": False}},
        })
    document = {"name": f"binary-v1-{role}-review", "cases": cases,
                "provenance": {"review_scope": REVIEW_SCOPE, "role": "development_review_only",
                               "source_run": diagnostic["run"], "training_input_pins": diagnostic["training_input_pins"],
                               "historical_labels_verified": False, "reserved_test_accessed": False}}
    ExperimentManifest.model_validate(document)
    return document


def build(run: Path, dataset: Path, output: Path) -> dict:
    output = output.resolve()
    if output.exists():
        raise FileExistsError("Choose a new directory; existing reviews must not be replaced")
    if any(output.is_relative_to(path.resolve()) for path in (run, dataset)):
        raise ValueError("Review output must be outside the frozen run and dataset")
    diagnostic, valid, _ = inspect(run, dataset)
    splits, pins = read_development(dataset)
    if pins != diagnostic["training_input_pins"]:
        raise ValueError("Dataset pins changed during review preparation")
    selection = json.loads((run / "data-selection.json").read_text())
    if file_hash(run / "data-selection.json") != diagnostic["input_pins"][str((run / "data-selection.json").resolve())]:
        raise ValueError("Training selection changed during review preparation")
    training = [row for row in selected_training(splits, selection) if row["swc"] == PAIR_PLAN["property"]]
    contrasts = contrast_pairs(training)
    seen = set(json.loads((run / "run.json").read_text())["trained_row_ids"])
    cohorts = {"validation": list(valid.values()), "training": training}
    manifests = {role: review_manifest(rows, output, role, diagnostic, seen) for role, rows in cohorts.items()}
    output.mkdir(parents=True)
    for role, rows in cohorts.items():
        for row in rows:
            project = output / "sources" / role / row["id"]
            project.mkdir(parents=True)
            (project / "Case.sol").write_text(source_and_target(row)[0], encoding="utf-8")
        manifest = output / f"{role}-manifest.json"
        write_json(manifest, manifests[role])
        prepare(manifest, output / role)
    write_json(output / "training-contrast-candidates.json", contrasts)
    write_json(output / "verified-original-diagnostic.json", diagnostic)
    summary = {
        "status": "prepared_not_reviewed", "output": str(output),
        "validation_cases": len(valid), "training_cases": len(training), "training_pairs": len(contrasts["pairs"]),
        "unpaired_training_cases": len(contrasts["unpaired_ids"]),
        "validation_counts": dict(sorted(Counter(f"{row['swc']}:{str(source_and_target(row)[1]['vulnerable']).lower()}"
                                                for row in valid.values()).items())),
        "reviewers_required_per_cohort": 2, "reviews_completed": 0,
        "implementation_sha256": {str(path.relative_to(ROOT)): file_hash(path) for path in (
            Path(__file__), ROOT / "scripts/label_review.py", ROOT / "training/diagnose_binary.py")},
        "artifact_sha256": {str(path.relative_to(output)): file_hash(path)
                            for path in sorted(output.rglob("*")) if path.is_file()},
        "reserved_test_accessed": False, "model_updated": False, "labels_changed": False,
        "approved_for_training": False, "claim_99_percent_supported": False,
        "scope": "Preparation only, not completed human review, new benchmark results or an accuracy improvement. "
                 "Give reviewers only one cohort's blind directory and the independent review instructions.",
    }
    write_json(output / "preparation.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, default=ROOT / "training/runs/mac-binary-v1")
    parser.add_argument("--dataset", type=Path, default=ROOT / "datasets/model-properties")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = build(args.run, args.dataset, args.output)
    print(json.dumps({key: result[key] for key in ("status", "output", "validation_cases", "training_cases", "training_pairs")}, indent=2))


if __name__ == "__main__":
    main()
