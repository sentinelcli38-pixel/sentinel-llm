"""Audit the requested precision target without changing predictions or old reports."""

import argparse
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sentinel.modeling.property_scoring import parse_property, score_properties
from training.binary_mlx import (
    probability,
    source_and_target,
    wilson_interval,
    write_json,
)
from training.frozen_probe import load_protocol, validate_receipt
from training.lexical_scale import load as load_scale
from training.local_model import file_hash

TARGET = {"precision": 0.99, "minimum_recall": 0.8, "minimum_specificity": 0.8,
          "minimum_positives_and_negatives_per_property": 20,
          "precision_interval_confidence": 0.95, "minimum_precision_interval_lower_bound": 0.99,
          "scope": "Apply overall and per property; not permission to drop cases or hide unresolved labels."}


def verify_report(report: dict, rows: list[dict]) -> None:
    predictions = report["predictions"]
    expected = {row["id"]: source_and_target(row)[1] for row in rows}
    if (len(rows) != len(expected) or len(predictions) != len(rows)
            or {row["id"] for row in predictions} != expected.keys()):
        raise ValueError("Audit requires the entire frozen evaluation cohort exactly once")
    for row in predictions:
        target = parse_property(row["expected"])
        actual = parse_property(row["prediction"], target["swc"])
        margin, score = row["classifier_margin"], row["classifier_score"]
        if (target != expected[row["id"]] or type(margin) not in (int, float) or not math.isfinite(margin)
                or type(score) not in (int, float) or not math.isfinite(score)
                or abs(probability([0.0, margin]) - score) > 1e-12
                or actual["vulnerable"] != (score > 0.5)):
            raise ValueError("Labels, fixed-threshold predictions or classifier margins differ")
    if score_properties(predictions) != report["scores"]:
        raise ValueError("Reported metrics differ from complete predictions")


def assess(scores: dict) -> dict:
    scopes = {"overall": scores, **scores["per_swc"]}
    failures, intervals = {}, {}
    for scope, item in scopes.items():
        errors = []
        for name, limit in (("precision", TARGET["precision"]), ("recall", TARGET["minimum_recall"]),
                            ("specificity", TARGET["minimum_specificity"])):
            if item[name] is None or item[name] < limit:
                errors.append(f"{name} is unavailable or below {limit}")
        interval = wilson_interval(item["tp"], item["tp"] + item["fp"])
        intervals[scope] = interval
        if interval["lower"] is None or interval["lower"] < TARGET["minimum_precision_interval_lower_bound"]:
            errors.append("Nominal 95% precision interval lower bound does not reach 0.99")
        if item["invalid_positive"] or item["invalid_negative"]:
            errors.append("Invalid assessments remain failures")
        if scope != "overall" and min(item["tp"] + item["fn"] + item["invalid_positive"],
                                      item["tn"] + item["fp"] + item["invalid_negative"]) < TARGET["minimum_positives_and_negatives_per_property"]:
            errors.append("Insufficient positive or negative property support")
        failures[scope] = errors
    return {"target": TARGET, "numerical_requirements_met": not any(failures.values()),
            "failures": failures, "precision_intervals": intervals,
            "independent_99_percent_claim_supported": False,
            "evidence_failures": ["These are development data, not an independent external assessment",
                                  "Historical labels and compiler/dependency context remain unreviewed"],
            "interval_caution": "Nominal casewise binomial intervals do not establish independent sampling, "
                                "repair label errors or account for correlated cases."}


def audit(probe: Path, scale: Path, output: Path) -> dict:
    if output.exists():
        raise FileExistsError("Preserve earlier target audits; choose a new path")
    _, probe_rows = load_protocol(probe)
    validate_receipt(probe, probe_rows, json.loads((probe / "features.json").read_text()))
    protocol, scale_rows = load_scale(scale)
    if any(output.resolve().is_relative_to(path.resolve()) for path in (probe, scale)):
        raise ValueError("Target audit must not be written inside frozen experiments")
    before = json.loads((probe / "comparison.json").read_text())
    after = json.loads((scale / "comparison.json").read_text())
    if (before["protocol_sha256"] != file_hash(probe / "protocol.json")
            or before["features_receipt_sha256"] != file_hash(probe / "features.json")
            or after["protocol_sha256"] != file_hash(scale / "protocol.json")
            or before["classifiers_sha256"] != file_hash(probe / "classifiers.json")
            or after["classifiers_sha256"] != file_hash(scale / "classifiers.json")):
        raise ValueError("Comparison evidence or classifier artifacts differ")
    valid_by_id = {row["id"]: row for row in scale_rows["valid"]}
    cohorts = {
        "frozen_qwen_54": (before["results"]["frozen_qwen"]["valid"], probe_rows["valid"]),
        "lexical_control_54": (before["results"]["lexical_control"]["valid"], probe_rows["valid"]),
        "lexical_scale_821": (after["full_validation"], scale_rows["valid"]),
        "lexical_scale_original_54": (after["original_validation_subset"], [valid_by_id[key] for key in protocol["original_valid_ids"]]),
    }
    results = {}
    for name, (report, rows) in cohorts.items():
        verify_report(report, rows)
        results[name] = {"cases": len(rows), "scores": report["scores"], "target_audit": assess(report["scores"])}
    paths = [directory / name for directory in (probe, scale) for name in ("protocol.json", "classifiers.json", "comparison.json")]
    paths.extend([probe / "features.json", probe / "features.npz"])
    document = {"results": results, "target": TARGET,
                "input_sha256": {str(path.resolve()): file_hash(path) for path in paths},
                "audit_implementation_sha256": file_hash(Path(__file__)),
                "reserved_test_accessed": False, "predictions_changed": False,
                "independent_99_percent_claim_supported": False,
                "scope": "Separate target audit, not a change to the original development gates, model or reports. "
                         "Overlapping cohorts and methods are not independent experiments or repeated confirmation."}
    output.parent.mkdir(parents=True, exist_ok=True)
    write_json(output, document)
    return {name: result["target_audit"]["numerical_requirements_met"] for name, result in results.items()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, default=ROOT / "training/runs/mac-frozen-probe-v1")
    parser.add_argument("--scale", type=Path, default=ROOT / "training/runs/mac-lexical-scale-v1")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.probe, args.scale, args.output), indent=2))


if __name__ == "__main__":
    main()
