"""Retrospective, opt-in evidence triage; never relabel cases or certify accuracy."""

import argparse
import hashlib
import json
import math
import platform
import sys
from collections import defaultdict
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from statistics import NormalDist

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sentinel.benchmark import summarize_benchmark
from sentinel.coverage import coverage_complete
from sentinel.detection import finding_class, normalized_class
from sentinel.experiments import PROFILES, ExperimentManifest
from sentinel.schemas.state import RuntimeState
from sentinel.schemas.vulnerability import FindingStatus, VulnerabilityFinding

POLICY = {
    "name": "same-node-unchecked-call-v1",
    "priority_property": "unchecked_low_level_calls",
    "minimum_qualitative_confidence": "medium",
    "minimum_impact": "medium",
    "required_sources": ["slither", "sentinel-static"],
    "slither_detectors": ["unchecked-send", "unchecked-lowlevel"],
    "static_detector": "unused-call-result",
    "match": "Exact target file, execution/declaration contract, function signature, AST byte span and node text.",
    "target_precision": 0.99,
    "minimum_recall": 0.8,
    "minimum_per_label_per_property": 20,
    "interval_confidence_level": 0.95,
    "scope": "Prioritized candidates only. Correlated checks share Slither; no independent confirmation or probability score.",
}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def wilson_interval(successes: int, total: int) -> dict:
    if type(successes) is not int or type(total) is not int or not 0 <= successes <= total:
        raise ValueError("Interval requires integer counts, 0 <= successes <= total")
    result = {"method": "Wilson score, two-sided", "confidence_level": 0.95,
              "successes": successes, "total": total, "lower": None, "upper": None}
    if total:
        z = NormalDist().inv_cdf(0.975)
        proportion = successes / total
        denominator = 1 + z * z / total
        center = (proportion + z * z / (2 * total)) / denominator
        margin = z * math.sqrt(proportion * (1 - proportion) / total + z * z / (4 * total * total)) / denominator
        result.update(lower=max(0.0, center - margin), upper=min(1.0, center + margin))
    return result


def node_keys(finding: VulnerabilityFinding, source: bytes) -> tuple[set[tuple], str]:
    """Require exact compiler node evidence, not proximity or shared category alone."""
    if finding_class(finding) != POLICY["priority_property"]:
        return set(), "property_requires_manual_review"
    allowed = ((finding.source == "slither" and finding.detector in POLICY["slither_detectors"])
               or (finding.source == "sentinel-static" and finding.detector == POLICY["static_detector"]))
    if not allowed or finding.status == FindingStatus.DISCARDED:
        return set(), "unsupported_or_discarded_candidate"
    if finding.confidence not in {"medium", "high"} or finding.severity not in {"medium", "high", "critical"}:
        return set(), "insufficient_qualitative_confidence_or_impact"
    if not (finding.file and finding.contract and finding.function and finding.line
            and finding.line <= len(source.splitlines())):
        return set(), "missing_source_attribution"
    try:
        raw = json.loads(finding.raw_output)
    except (ValueError, TypeError):
        return set(), "missing_or_inconsistent_ast_evidence"
    if (not isinstance(raw, dict) or raw.get("check") != finding.detector
            or not isinstance(raw.get("confidence"), str) or raw["confidence"].lower() != finding.confidence
            or not isinstance(raw.get("impact"), str) or raw["impact"].lower() != finding.severity):
        return set(), "missing_or_inconsistent_ast_evidence"
    fields = raw.get("additional_fields", {})
    if not isinstance(fields, dict):
        return set(), "missing_or_inconsistent_ast_evidence"
    if finding.source == "sentinel-static" and (fields.get("engine") != "slither-ssa" or fields.get("experimental") is not True):
        return set(), "missing_or_inconsistent_ast_evidence"
    elements = raw.get("elements")
    if not isinstance(elements, list):
        return set(), "missing_or_inconsistent_ast_evidence"
    keys = set()
    for node in elements:
        if not isinstance(node, dict) or node.get("type") != "node":
            continue
        mapping = node.get("source_mapping", {})
        node_fields = node.get("type_specific_fields", {})
        if not isinstance(mapping, dict) or not isinstance(node_fields, dict):
            continue
        function = node_fields.get("parent", {})
        if not isinstance(function, dict) or function.get("type") != "function":
            continue
        function_fields = function.get("type_specific_fields", {})
        if not isinstance(function_fields, dict):
            continue
        declaration = function_fields.get("parent", {})
        signature = function_fields.get("signature")
        if (not isinstance(declaration, dict) or declaration.get("type") != "contract"
                or not isinstance(signature, str) or not signature
                or function.get("name") != finding.function):
            continue
        declaring_contract = declaration.get("name")
        if fields.get("execution_contract") is not None:
            if (fields["execution_contract"] != finding.contract or fields.get("declaring_contract") != declaring_contract
                    or fields.get("function_signature") != signature
                    or fields.get("attribution") != "compiled-inherited-entry-point"):
                continue
        elif declaring_contract != finding.contract:
            continue
        start, length = mapping.get("start"), mapping.get("length")
        if (mapping.get("filename_relative") != finding.file or type(start) is not int or type(length) is not int
                or start < 0 or length < 1 or start + length > len(source)
                or not isinstance(node.get("name"), str) or not node["name"].strip()):
            continue
        first = source[:start].count(b"\n") + 1
        last = source[:start + length - 1].count(b"\n") + 1
        lines = mapping.get("lines")
        if (not isinstance(lines, list) or any(type(line) is not int for line in lines)
                or lines != list(range(first, last + 1))):
            continue
        keys.add((finding.file, finding.contract, declaring_contract, signature, start, length, node["name"], first, last))
    return keys, "no_same_node_corroboration" if keys else "missing_or_inconsistent_ast_evidence"


def triage(findings: list[VulnerabilityFinding], source: bytes) -> dict:
    if len({finding.id for finding in findings}) != len(findings):
        raise ValueError("Finding IDs must be unique")
    groups, reasons = defaultdict(list), {}
    for finding in findings:
        keys, reason = node_keys(finding, source)
        reasons[finding.id] = reason
        for key in keys:
            groups[key].append(finding)
    nodes, prioritized = [], set()
    for key, supporters in sorted(groups.items()):
        if {finding.source for finding in supporters} != set(POLICY["required_sources"]):
            continue
        ids = sorted(finding.id for finding in supporters)
        prioritized.update(ids)
        file, contract, declaration, signature, start, length, _, first, last = key
        nodes.append({"file": file, "contract": contract, "declaring_contract": declaration,
                      "function_signature": signature, "start": start, "length": length,
                      "first_line": first, "last_line": last, "supporting_finding_ids": ids})
    return {"prioritized_finding_ids": sorted(prioritized), "corroborated_nodes": nodes,
            "review_required": [{"finding_id": finding.id, "reason": reasons[finding.id]}
                                for finding in findings if finding.id not in prioritized]}


def metrics(rows: list[dict], prediction: str) -> dict:
    known = [row for row in rows if row["ground_truth"] != "unknown"]
    result = summarize_benchmark(
        sum(row[prediction] and row["ground_truth"] == "vulnerable" for row in known),
        sum(row[prediction] and row["ground_truth"] == "clean" for row in known),
        sum(not row[prediction] and row["ground_truth"] == "vulnerable" for row in known),
        sum(not row[prediction] and row["ground_truth"] == "clean" for row in known),
    ).model_dump(mode="json")
    if not any(row["ground_truth"] == "clean" for row in known):
        for field in ("precision", "f1_score", "false_positive_rate"):
            result[field] = None
    return result


def measured_summary(rows: list[dict]) -> dict:
    measured = metrics(rows, "prioritized")
    interval = wilson_interval(measured["true_positives"], measured["true_positives"] + measured["false_positives"])
    if measured["precision"] is None:
        interval.update(lower=None, upper=None)
    return {"candidate_metrics": metrics(rows, "detected"), "priority_metrics": measured,
            "precision_interval": interval,
            "prioritized_cases": sum(row["prioritized"] for row in rows),
            "deferred_candidate_cases": sum(row["detected"] and not row["prioritized"] for row in rows),
            "no_matching_candidate_cases": sum(not row["detected"] for row in rows),
            "unknown_label_cases": sum(row["ground_truth"] == "unknown" for row in rows)}


def pinned_source(manifest_path: Path, case) -> tuple[Path, bytes]:
    if not case.source_sha256 or not case.target_file or not case.target_contract:
        raise ValueError("Triage evaluation requires pinned, explicitly scoped targets")
    project = (manifest_path.parent / case.project_path).resolve()
    target = (project / case.target_file).resolve()
    if not target.is_relative_to(project):
        raise ValueError("Target escapes project")
    source = target.read_bytes()
    if sha(source) != case.source_sha256:
        raise ValueError("Target source differs from frozen assessment")
    for relative, expected in case.provenance.get("project_files_sha256", {}).items():
        dependency = (project / relative).resolve()
        if Path(relative).is_absolute() or not dependency.is_relative_to(project) or sha(dependency.read_bytes()) != expected:
            raise ValueError("Dependency/configuration differs from frozen assessment")
    return project, source


def evaluate(manifest_path: Path, report_path: Path) -> dict:
    manifest_bytes, report_bytes = manifest_path.read_bytes(), report_path.read_bytes()
    manifest = ExperimentManifest.model_validate_json(manifest_bytes)
    report = json.loads(report_bytes)
    if (report.get("manifest_sha256") != sha(manifest_bytes)
            or report.get("dataset_provenance") != manifest.provenance):
        raise ValueError("Report must match the exact frozen manifest and provenance")
    if not isinstance(manifest.provenance.get("scanner_protocol"), dict):
        raise TypeError("A frozen scanner protocol is required")
    if report.get("profile") != PROFILES["sentinel-static"].model_dump(mode="json"):
        raise ValueError("Corroboration requires the full sentinel-static scout profile")
    records = report.get("cases", [])
    by_id = {row["case_id"]: row for row in records}
    if len(by_id) != len(records) or set(by_id) != {case.id for case in manifest.cases}:
        raise ValueError("Report must contain every case exactly once")
    rows, ledger_pins = [], {}
    for case in manifest.cases:
        row = by_id[case.id]
        for key in ("ground_truth", "vulnerability_class", "target_contract", "target_file", "source_sha256", "provenance", "group"):
            if row.get(key) != getattr(case, key):
                raise ValueError(f"Assessment or scope mismatch: {case.id}/{key}")
        if (row.get("error") or any(row.get(key) is not True for key in ("coverage_complete", "label_supported", "attribution_complete"))
                or type(row.get("detected")) is not bool):
            raise ValueError("Incomplete/unsupported cases cannot be silently dropped or scored")
        project, source = pinned_source(manifest_path, case)
        ledger = Path(row["ledger"])
        ledger = ledger if ledger.is_absolute() else ROOT / ledger
        ledger = ledger.with_suffix(".json").resolve()
        expected_root = (report_path.parent / "ledgers/sentinel-static" / case.id).resolve()
        if not ledger.is_relative_to(expected_root):
            raise ValueError("Ledger must belong to this report, profile and case")
        ledger_bytes = ledger.read_bytes()
        state = RuntimeState.model_validate_json(ledger_bytes, strict=True)
        if (not coverage_complete(state) or not state.scout_only or state.experiment_profile != "sentinel-static"
                or state.enabled_analyzers != PROFILES["sentinel-static"].enabled_analyzers
                or Path(state.project_path).resolve() != project
                or state.final_verification_state != row.get("outcome")):
            raise ValueError("Ledger context or coverage differs from the experiment")
        statuses = [{"tool": run.tool, "target": run.target, "status": run.status} for run in state.analyzer_runs]
        if statuses != row.get("analyzer_statuses") or len(state.findings) != row.get("findings"):
            raise ValueError("Ledger analyzer statuses or finding count differs")
        if len({finding.id for finding in state.findings}) != len(state.findings):
            raise ValueError("Ledger finding IDs must be unique")
        category = [finding for finding in state.findings if finding_class(finding) == normalized_class(case.vulnerability_class)]
        relevant = [finding for finding in category if finding.file == case.target_file]
        if any(not finding.file for finding in category) or any(not finding.contract for finding in relevant):
            raise ValueError("Ledger attribution is incomplete")
        matched = [finding for finding in relevant if finding.contract == case.target_contract]
        if ([finding.id for finding in matched] != row.get("matched_finding_ids") or bool(matched) != row["detected"]
                or len(state.findings) - len(matched) != row.get("unmatched_findings")):
            raise ValueError("Ledger candidate evidence differs from original report")
        selection = triage(matched, source)
        rows.append({"case_id": case.id, "target_contract": case.target_contract,
                     "vulnerability_class": case.vulnerability_class, "ground_truth": case.ground_truth,
                     "source_sha256": case.source_sha256, "detected": row["detected"],
                     "prioritized": bool(selection["prioritized_finding_ids"]),
                     "out_of_scope_finding_ids": [finding.id for finding in state.findings if finding not in matched],
                     **selection})
        ledger_pins[case.id] = {"path": str(ledger), "sha256": sha(ledger_bytes)}
    summary = measured_summary(rows)
    if summary["candidate_metrics"] != report.get("metrics"):
        raise ValueError("Original metrics disagree with complete case predictions")
    by_property = {category: measured_summary([row for row in rows if row["vulnerability_class"] == category])
                   for category in sorted({row["vulnerability_class"] for row in rows})}
    samples_sufficient = all(
        item["priority_metrics"]["true_positives"] + item["priority_metrics"]["false_negatives"] >= POLICY["minimum_per_label_per_property"]
        and item["priority_metrics"]["true_negatives"] + item["priority_metrics"]["false_positives"] >= POLICY["minimum_per_label_per_property"]
        for item in by_property.values())
    precision, recall = summary["priority_metrics"]["precision"], summary["priority_metrics"]["recall"]
    lower = summary["precision_interval"]["lower"]
    dependencies = [Path(__file__), ROOT / "sentinel/benchmark.py", ROOT / "sentinel/detection.py",
                    ROOT / "sentinel/coverage.py", ROOT / "sentinel/experiments.py",
                    *sorted((ROOT / "sentinel/schemas").glob("*.py"))]
    property_recall = all(item["priority_metrics"]["recall"] is not None
                          and item["priority_metrics"]["recall"] >= POLICY["minimum_recall"] for item in by_property.values())
    property_precision = all(item["precision_interval"]["lower"] is not None
                            and item["precision_interval"]["lower"] >= POLICY["target_precision"] for item in by_property.values())
    return {"schema_version": 1, "created_at": datetime.now(UTC).isoformat(), "policy": POLICY,
            "runtime": {"python": platform.python_version(), "pydantic": version("pydantic")},
            "input_pins": {"manifest": {"path": str(manifest_path.resolve()), "sha256": sha(manifest_bytes)},
                           "report": {"path": str(report_path.resolve()), "sha256": sha(report_bytes)},
                           "ledgers": ledger_pins,
                           "implementation_sha256": {str(path.relative_to(ROOT)): sha(path.read_bytes()) for path in dependencies}},
            "evaluation_role": "retrospective_development_only", "cases_total": len(rows),
            "coverage_complete_cases": len(rows), **summary, "by_vulnerability_class": by_property,
            "original_qualification": report.get("qualification"),
            "target_assessment": {
                "observed_precision_at_least_99_percent": precision is not None and precision >= 0.99,
                "precision_interval_lower_at_least_99_percent": lower is not None and lower >= 0.99,
                "overall_recall_at_least_80_percent": recall is not None and recall >= 0.8,
                "all_property_recall_at_least_80_percent": property_recall,
                "all_property_precision_interval_lower_at_least_99_percent": property_precision,
                "property_sample_counts_sufficient": samples_sufficient,
                "claim_supported": False,
                "limitations": ["Retrospective development data; not a new independent evaluation.",
                                "Priority eligibility currently covers unchecked calls only; other properties remain review-required.",
                                "Shared Slither infrastructure means corroboration is not independent validation.",
                                "Case/property labels do not confirm each individual finding or exploitability.",
                                "A Wilson interval assumes independent binomial observations; corpus dependence and selection can invalidate population interpretation.",
                                "Independent expert label evidence and a representative untouched benchmark are still required."]},
            "scope": "All cases retained. Deferred positives count as false negatives in priority metrics; unknown labels are never invented. "
                     "No matching candidate does not mean safe. Analyzer confidence is qualitative, not calibrated probability. "
                     "No scans, model inference, RPC, exploit or repair execution. Original reports and detector code are unchanged.",
            "cases": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--require-target", action="store_true", help="Exit 2 unless a validated 99%% claim is supported")
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("Choose a new report path; previous evidence is never overwritten")
    result = evaluate(args.manifest, args.report)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(result, indent=2) + "\n")
    print(f"Triage report: {args.output}; priority precision: {result['priority_metrics']['precision']}; "
          f"recall: {result['priority_metrics']['recall']}; validated 99% claim: False")
    if args.require_target and not result["target_assessment"]["claim_supported"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
