"""Compare complete frozen scanner runs without selecting or changing assessments."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.benchmark import summarize_benchmark
from sentinel.experiments import ExperimentManifest


def assessed_cases(report: dict, manifest: ExperimentManifest, digest: str, profile: str) -> dict:
    if report.get("manifest_sha256") != digest or report.get("profile", {}).get("name") != profile:
        raise ValueError("Reports must match the exact frozen manifest and expected profiles")
    if report.get("dataset_provenance") != manifest.provenance:
        raise ValueError("Report provenance differs from the manifest")
    rows = report.get("cases", [])
    cases = {row["case_id"]: row for row in rows}
    if len(cases) != len(rows) or set(cases) != {case.id for case in manifest.cases}:
        raise ValueError("Reports must contain every manifest case exactly once")
    for expected in manifest.cases:
        row = cases[expected.id]
        if not expected.source_sha256 or not expected.target_contract or not expected.target_file:
            raise ValueError(f"Paired comparison requires a pinned assessed target: {expected.id}")
        for key in ("ground_truth", "vulnerability_class", "target_contract", "target_file", "source_sha256", "provenance", "group"):
            if row.get(key) != getattr(expected, key):
                raise ValueError(f"Case assessment or scope differs: {expected.id}/{key}")
        if (expected.ground_truth == "unknown" or row.get("error")
                or row.get("coverage_complete") is not True or row.get("label_supported") is not True
                or row.get("attribution_complete") is not True or type(row.get("detected")) is not bool):
            raise ValueError(f"Incomplete or unassessed case cannot enter paired metrics: {expected.id}")
    return cases


def metrics(rows: list[dict]) -> dict:
    counts = {"true_positives": 0, "false_positives": 0, "false_negatives": 0, "true_negatives": 0}
    for row in rows:
        positive = row["ground_truth"] == "vulnerable"
        key = ("true_positives" if positive else "false_positives") if row["detected"] else (
            "false_negatives" if positive else "true_negatives")
        counts[key] += 1
    return summarize_benchmark(**counts).model_dump(mode="json")


def compare(manifest_bytes: bytes, baseline: dict, extended: dict) -> dict:
    manifest = ExperimentManifest.model_validate_json(manifest_bytes)
    protocol = manifest.provenance.get("scanner_protocol")
    if protocol is None:
        raise ValueError("Comparison requires a frozen scanner protocol")
    if not isinstance(protocol, dict):
        raise TypeError("Frozen scanner protocol must be an object")
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    before = assessed_cases(baseline, manifest, digest, "slither")
    after = assessed_cases(extended, manifest, digest, "sentinel-static")
    for report, cases in ((baseline, before), (extended, after)):
        if report.get("metrics") != metrics(list(cases.values())):
            raise ValueError("Reported metrics disagree with complete case predictions")
    changed = [{"case_id": case.id, "target_contract": case.target_contract,
                "vulnerability_class": case.vulnerability_class, "ground_truth": case.ground_truth,
                "baseline_detected": before[case.id]["detected"], "extended_detected": after[case.id]["detected"]}
               for case in manifest.cases if before[case.id]["detected"] != after[case.id]["detected"]]
    properties = {}
    for category in sorted({case.vulnerability_class for case in manifest.cases}):
        ids = [case.id for case in manifest.cases if case.vulnerability_class == category]
        properties[category] = {"baseline": metrics([before[key] for key in ids]),
                                "extended": metrics([after[key] for key in ids])}
    return {"manifest_sha256": digest, "cases": len(before), "baseline": baseline["metrics"],
            "extended": extended["metrics"], "by_vulnerability_class": properties,
            "changed_predictions": changed,
            "qualification": {"baseline": baseline["qualification"], "extended": extended["qualification"]},
            "scope": "Paired case/property candidate predictions on the same frozen assessments. "
                     "Not independent label adjudication, exploitability, model performance, or production certification."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--extended", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    baseline_bytes, extended_bytes = args.baseline.read_bytes(), args.extended.read_bytes()
    result = compare(args.manifest.read_bytes(), json.loads(baseline_bytes), json.loads(extended_bytes))
    result["report_pins"] = {name: {"path": str(path.resolve()), "sha256": hashlib.sha256(raw).hexdigest()}
                             for name, path, raw in (("baseline", args.baseline, baseline_bytes),
                                                     ("extended", args.extended, extended_bytes))}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(result, indent=2) + "\n")
    print(f"Paired comparison: {args.output}; changed cases: {len(result['changed_predictions'])}")


if __name__ == "__main__":
    main()
