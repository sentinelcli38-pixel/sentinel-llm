import copy
import json
from pathlib import Path

import pytest

from scripts.precision_triage import (
    evaluate,
    main,
    measured_summary,
    metrics,
    node_keys,
    sha,
    triage,
    wilson_interval,
)
from sentinel.experiments import PROFILES
from sentinel.schemas.state import RuntimeState
from sentinel.schemas.vulnerability import FindingStatus, VulnerabilityFinding

SOURCE = b'contract Example {\nfunction ping() external {\naddress(0).call("");\n}\n}\n'
NODE = 'address(0).call("")'


def finding(tool="slither", **updates):
    detector = "unchecked-lowlevel" if tool == "slither" else "unused-call-result"
    raw = {"check": detector, "confidence": "Medium", "impact": "Medium", "elements": [{
        "type": "node", "name": NODE,
        "source_mapping": {"filename_relative": "src/Case.sol", "start": SOURCE.index(NODE.encode()),
                           "length": len(NODE), "lines": [3]},
        "type_specific_fields": {"parent": {"type": "function", "name": "ping", "type_specific_fields": {
            "signature": "ping()", "parent": {"type": "contract", "name": "Example"}}}},
    }]}
    if tool == "sentinel-static":
        raw["additional_fields"] = {"engine": "slither-ssa", "experimental": True}
    return VulnerabilityFinding(id=f"{tool}-case", source=tool, detector=detector,
                                file="src/Case.sol", contract="Example", function="ping", line=3,
                                confidence="medium", severity="medium", confidence_score=0.6,
                                description="Unit-test candidate, not a reviewed vulnerability.",
                                raw_output=json.dumps(raw)).model_copy(update=updates)


def mutate_raw(candidate, operation):
    raw = json.loads(candidate.raw_output)
    operation(raw)
    return candidate.model_copy(update={"raw_output": json.dumps(raw)})


def fixture_reports(tmp_path):
    root = tmp_path / "reports"
    cases, rows, ledgers = [], [], {}
    definitions = [("positive", "vulnerable", "unchecked_low_level_calls", [finding(), finding("sentinel-static")]),
                   ("negative", "clean", "unchecked_low_level_calls", []),
                   ("missed", "vulnerable", "unchecked_low_level_calls", []),
                   ("deferred", "vulnerable", "unchecked_low_level_calls", [finding("sentinel-static")]),
                   ("reentrant", "vulnerable", "reentrancy", [finding(detector="reentrancy-eth")]),
                   ("unknown", "unknown", "unchecked_low_level_calls", [finding(), finding("sentinel-static")])]
    for case_id, truth, category, findings in definitions:
        project = tmp_path / "projects" / case_id
        (project / "src").mkdir(parents=True)
        (project / "src/Case.sol").write_bytes(SOURCE)
        case = {"id": case_id, "project_path": str(project), "target_file": "src/Case.sol",
                "target_contract": "Example", "ground_truth": truth, "vulnerability_class": category,
                "source_sha256": sha(SOURCE), "group": "development", "provenance": {}}
        cases.append(case)
        ledger = root / "ledgers/sentinel-static" / case_id / "scan.json"
        ledger.parent.mkdir(parents=True)
        statuses = [{"tool": tool, "target": ".", "status": "completed"} for tool in ("slither", "sentinel-static")]
        state = RuntimeState(project_path=str(project), scout_only=True, experiment_profile="sentinel-static",
                             enabled_analyzers=["slither", "sentinel-static"], analyzer_runs=statuses,
                             findings=findings, final_verification_state="scout_complete")
        ledger.write_text(state.json_ledger())
        ledgers[case_id] = ledger
        row = {**{key: value for key, value in case.items() if key not in {"id", "project_path"}},
               "case_id": case_id, "detected": bool(findings), "coverage_complete": True, "label_supported": True,
               "attribution_complete": True, "error": "", "matched_finding_ids": [f.id for f in findings],
               "findings": len(findings), "unmatched_findings": 0, "analyzer_statuses": statuses,
               "outcome": "scout_complete", "ledger": str(ledger.with_suffix(".md"))}
        rows.append(row)
    manifest = {"name": "unit-test-only", "cases": cases, "provenance": {"scanner_protocol": {"unit_test": True}}}
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    report = {"manifest_sha256": sha(manifest_path.read_bytes()), "dataset_provenance": manifest["provenance"],
              "profile": PROFILES["sentinel-static"].model_dump(mode="json"), "cases": rows,
              "metrics": metrics(rows, "detected"), "qualification": {"passed": False}}
    report_path = root / "experiment.json"
    report_path.write_text(json.dumps(report))
    return manifest_path, report_path, ledgers


def test_only_same_node_with_distinct_checks_is_prioritized():
    result = triage([finding(), finding("sentinel-static")], SOURCE)
    assert result["prioritized_finding_ids"] == ["sentinel-static-case", "slither-case"]
    assert not result["review_required"]
    assert len(result["corroborated_nodes"]) == 1
    assert result["corroborated_nodes"][0]["first_line"] == 3


def test_duplicate_source_does_not_supply_corroboration():
    result = triage([finding(), finding(id="another-slither")], SOURCE)
    assert not result["prioritized_finding_ids"]
    assert len(result["review_required"]) == 2
    with pytest.raises(ValueError, match="unique"):
        triage([finding(), finding()], SOURCE)


@pytest.mark.parametrize("mode", ["file", "contract", "function", "signature", "span", "text", "line",
                                  "bool_offset", "bool_line", "negative_offset", "outside_source", "empty_node",
                                  "parent", "engine", "raw_check", "raw_confidence", "raw_confidence_type",
                                  "raw_impact", "no_raw", "no_nodes", "low_confidence", "low_impact", "discarded"])
def test_inconsistent_or_insufficient_evidence_stays_in_review(mode):
    candidate = finding("sentinel-static")
    if mode in {"file", "contract", "function"}:
        candidate = candidate.model_copy(update={mode: "different"})
    elif mode == "line":
        candidate = candidate.model_copy(update={"line": 999})
    elif mode == "no_raw":
        candidate = candidate.model_copy(update={"raw_output": "invalid"})
    elif mode == "low_confidence":
        candidate = candidate.model_copy(update={"confidence": "low", "confidence_score": 0.99})
    elif mode == "low_impact":
        candidate = candidate.model_copy(update={"severity": "low"})
    elif mode == "discarded":
        candidate = candidate.model_copy(update={"status": FindingStatus.DISCARDED})
    else:
        def change(raw):
            node = raw["elements"][0]
            mapping = node["source_mapping"]
            if mode == "signature":
                node["type_specific_fields"]["parent"]["type_specific_fields"]["signature"] = "ping(address)"
            elif mode == "span":
                mapping["start"] += 1
                mapping["length"] -= 1
            elif mode == "text":
                node["name"] = "different expression"
            elif mode == "bool_offset":
                mapping["start"] = True
            elif mode == "bool_line":
                mapping["lines"] = [True]
            elif mode == "negative_offset":
                mapping["start"] = -1
            elif mode == "outside_source":
                mapping["length"] = 10000
            elif mode == "empty_node":
                mapping["length"] = 0
            elif mode == "parent":
                node["type_specific_fields"]["parent"] = []
            elif mode == "engine":
                raw["additional_fields"]["engine"] = "invented"
            elif mode == "raw_check":
                raw["check"] = "unchecked-send"
            elif mode == "raw_confidence":
                raw["confidence"] = "High"
            elif mode == "raw_confidence_type":
                raw["confidence"] = []
            elif mode == "raw_impact":
                raw["impact"] = "High"
            elif mode == "no_nodes":
                raw["elements"] = []
        candidate = mutate_raw(candidate, change)
    result = triage([finding(), candidate], SOURCE)
    assert not result["prioritized_finding_ids"]
    assert len(result["review_required"]) == 2


def test_different_call_nodes_on_same_line_do_not_corroborate():
    source = SOURCE.replace(NODE.encode(), f"{NODE}; {NODE}".encode())
    other = mutate_raw(finding("sentinel-static"), lambda raw: raw["elements"][0]["source_mapping"].update(
        start=source.rindex(NODE.encode())))
    assert not triage([finding(), other], source)["prioritized_finding_ids"]


def test_non_ascii_offsets_are_bytes_not_characters():
    prefix = "// Unit-test UTF-8: \u03c0\n".encode()
    source = prefix + SOURCE
    candidates = [mutate_raw(finding(tool), lambda raw: raw["elements"][0]["source_mapping"].update(
        start=len(prefix) + SOURCE.index(NODE.encode()), lines=[4])) for tool in ("slither", "sentinel-static")]
    assert len(triage(candidates, source)["prioritized_finding_ids"]) == 2


def test_compiled_inheritance_metadata_must_match_declaration_and_signature():
    def inheritance(raw):
        raw.setdefault("additional_fields", {}).update(execution_contract="Child", declaring_contract="Example",
                                                       function_signature="ping()", attribution="compiled-inherited-entry-point")
    candidates = [mutate_raw(finding(tool, contract="Child"), inheritance) for tool in ("slither", "sentinel-static")]
    assert len(triage(candidates, SOURCE)["prioritized_finding_ids"]) == 2
    wrong = mutate_raw(candidates[1], lambda raw: raw["additional_fields"].update(declaring_contract="Wrong"))
    assert not triage([candidates[0], wrong], SOURCE)["prioritized_finding_ids"]


def test_other_properties_are_not_relabelled_safe_even_with_high_score():
    candidate = finding(detector="reentrancy-eth", confidence="high", confidence_score=0.99)
    result = triage([candidate], SOURCE)
    assert result["review_required"] == [{"finding_id": candidate.id, "reason": "property_requires_manual_review"}]


def test_single_checker_cannot_be_promoted_by_inventing_a_probability():
    candidate = finding(confidence_score=0.99)
    assert node_keys(candidate, SOURCE)[0]
    assert not triage([candidate], SOURCE)["prioritized_finding_ids"]


def test_deferred_positives_remain_false_negatives_and_unknown_labels_stay_unknown(tmp_path):
    manifest, report, ledgers = fixture_reports(tmp_path)
    original_manifest, original_report = manifest.read_bytes(), report.read_bytes()
    original_ledgers = {key: path.read_bytes() for key, path in ledgers.items()}
    result = evaluate(manifest, report)
    assert result["cases_total"] == result["coverage_complete_cases"] == 6
    assert result["candidate_metrics"]["recall"] == 0.75
    assert result["priority_metrics"]["precision"] == 1
    assert result["priority_metrics"]["recall"] == 0.25
    assert result["priority_metrics"]["false_negatives"] == 3
    assert result["priority_metrics"]["evaluated"] == 5
    assert result["unknown_label_cases"] == 1
    assert result["prioritized_cases"] == 2
    assert result["deferred_candidate_cases"] == 2
    assert not result["target_assessment"]["claim_supported"]
    assert not result["target_assessment"]["precision_interval_lower_at_least_99_percent"]
    assert result["original_qualification"] == {"passed": False}
    assert manifest.read_bytes() == original_manifest and report.read_bytes() == original_report
    assert all(path.read_bytes() == original_ledgers[key] for key, path in ledgers.items())


@pytest.mark.parametrize("mode", ["manifest", "provenance", "profile", "missing", "duplicate", "scope", "label",
                                  "source_pin", "source_bytes", "coverage", "attribution", "supported", "error",
                                  "prediction_type", "prediction", "matched_ids", "metrics", "ledger_escape",
                                  "ledger_profile", "ledger_mock", "ledger_coverage", "ledger_project", "ledger_statuses",
                                  "ledger_duplicate_ids", "finding_count", "unmatched_count", "dependency"])
def test_incomplete_tampered_or_mixed_evidence_is_rejected(tmp_path, mode):
    manifest, report_path, ledgers = fixture_reports(tmp_path)
    report = json.loads(report_path.read_text())
    row = report["cases"][0]
    if mode == "manifest":
        report["manifest_sha256"] = "0" * 64
    elif mode == "provenance":
        report["dataset_provenance"] = {}
    elif mode == "profile":
        report["profile"] = PROFILES["slither"].model_dump(mode="json")
    elif mode == "missing":
        report["cases"].pop()
    elif mode == "duplicate":
        report["cases"].append(copy.deepcopy(row))
    elif mode == "scope":
        row["target_contract"] = "Wrong"
    elif mode == "label":
        row["ground_truth"] = "clean"
    elif mode == "source_pin":
        row["source_sha256"] = "0" * 64
    elif mode == "source_bytes":
        (tmp_path / "projects/positive/src/Case.sol").write_bytes(b"changed")
    elif mode in {"coverage", "attribution", "supported"}:
        key = {"coverage": "coverage_complete", "attribution": "attribution_complete", "supported": "label_supported"}[mode]
        row[key] = False
    elif mode == "error":
        row["error"] = "scanner failed"
    elif mode == "prediction_type":
        row["detected"] = "true"
    elif mode == "prediction":
        row["detected"] = False
    elif mode == "matched_ids":
        row["matched_finding_ids"] = []
    elif mode == "metrics":
        report["metrics"]["precision"] = 0.99
    elif mode == "ledger_escape":
        row["ledger"] = str(ledgers["unknown"])
    elif mode in {"finding_count", "unmatched_count"}:
        row["findings" if mode == "finding_count" else "unmatched_findings"] = 999
    elif mode == "dependency":
        document = json.loads(manifest.read_text())
        document["cases"][0]["provenance"]["project_files_sha256"] = {"src/Case.sol": "0" * 64}
        manifest.write_text(json.dumps(document))
        report["manifest_sha256"] = sha(manifest.read_bytes())
        row["provenance"] = document["cases"][0]["provenance"]
    else:
        state = json.loads(ledgers["positive"].read_text())
        if mode == "ledger_profile":
            state["experiment_profile"] = "sentinel-full"
        elif mode == "ledger_mock":
            state["mock_mode"] = True
        elif mode == "ledger_coverage":
            state["analyzer_runs"][0]["status"] = "timed_out"
        elif mode == "ledger_project":
            state["project_path"] = str(tmp_path)
        elif mode == "ledger_statuses":
            state["analyzer_runs"][0]["target"] = "changed.sol"
        elif mode == "ledger_duplicate_ids":
            state["findings"][1]["id"] = state["findings"][0]["id"]
        ledgers["positive"].write_text(json.dumps(state))
    report_path.write_text(json.dumps(report))
    with pytest.raises(ValueError):
        evaluate(manifest, report_path)


def test_zero_prioritized_cases_is_not_perfect_precision():
    rows = [{"ground_truth": "vulnerable", "detected": True, "prioritized": False},
            {"ground_truth": "clean", "detected": True, "prioritized": False}]
    result = measured_summary(rows)
    assert result["priority_metrics"]["precision"] is None
    assert result["priority_metrics"]["recall"] == 0
    assert result["precision_interval"]["lower"] is None


def test_corroborated_false_positive_is_counted_not_silently_relabelled(tmp_path):
    manifest, report_path, ledgers = fixture_reports(tmp_path)
    state = json.loads(ledgers["positive"].read_text())
    state["project_path"] = str(tmp_path / "projects/negative")
    ledgers["negative"].write_text(json.dumps(state))
    report = json.loads(report_path.read_text())
    negative = next(row for row in report["cases"] if row["case_id"] == "negative")
    negative.update(detected=True, findings=2, matched_finding_ids=[f["id"] for f in state["findings"]])
    report["metrics"] = metrics(report["cases"], "detected")
    report_path.write_text(json.dumps(report))
    result = evaluate(manifest, report_path)
    assert result["priority_metrics"]["false_positives"] == 1
    assert result["priority_metrics"]["precision"] == 0.5
    assert next(row for row in result["cases"] if row["case_id"] == "negative")["ground_truth"] == "clean"
    assert not result["target_assessment"]["observed_precision_at_least_99_percent"]


def test_complete_unknown_label_cohort_never_invents_accuracy(tmp_path):
    manifest_path, report_path, _ = fixture_reports(tmp_path)
    manifest = json.loads(manifest_path.read_text())
    report = json.loads(report_path.read_text())
    for case, row in zip(manifest["cases"], report["cases"], strict=True):
        case["ground_truth"] = row["ground_truth"] = "unknown"
    manifest_path.write_text(json.dumps(manifest))
    report["manifest_sha256"] = sha(manifest_path.read_bytes())
    report["metrics"] = metrics(report["cases"], "detected")
    report_path.write_text(json.dumps(report))
    result = evaluate(manifest_path, report_path)
    assert result["unknown_label_cases"] == result["cases_total"] == 6
    assert result["priority_metrics"]["evaluated"] == 0
    assert result["priority_metrics"]["precision"] is None
    assert result["priority_metrics"]["recall"] is None
    assert not result["target_assessment"]["claim_supported"]


def test_no_negative_controls_or_unknown_only_does_not_establish_precision():
    for truth in ("vulnerable", "unknown"):
        result = measured_summary([{"ground_truth": truth, "detected": True, "prioritized": True}])
        assert result["priority_metrics"]["precision"] is None
        assert result["precision_interval"]["lower"] is None


def test_wilson_intervals_do_not_certify_tiny_perfect_samples():
    assert wilson_interval(0, 0)["lower"] is None
    assert wilson_interval(10, 10)["lower"] == pytest.approx(0.7224672001371107)
    assert wilson_interval(100, 100)["lower"] < 0.99
    assert wilson_interval(1000, 1000)["lower"] > 0.99
    assert wilson_interval(0, 10)["upper"] == pytest.approx(1 - wilson_interval(10, 10)["lower"])
    assert wilson_interval(200, 1000)["lower"] < 0.2 < wilson_interval(200, 1000)["upper"]


@pytest.mark.parametrize("successes,total", [(-1, 2), (3, 2), (True, 2), (1, 2.0)])
def test_interval_rejects_invalid_counts(successes, total):
    with pytest.raises(ValueError):
        wilson_interval(successes, total)


def test_cli_pins_inputs_refuses_overwrite_and_target_gate_fails_closed(tmp_path, monkeypatch):
    manifest, report, ledgers = fixture_reports(tmp_path)
    output = tmp_path / "triage.json"
    monkeypatch.setattr("sys.argv", ["triage", "--manifest", str(manifest), "--report", str(report),
                                     "--output", str(output), "--require-target"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 2
    result = json.loads(output.read_text())
    assert result["input_pins"]["manifest"]["sha256"] == sha(manifest.read_bytes())
    assert result["input_pins"]["report"]["sha256"] == sha(report.read_bytes())
    assert result["input_pins"]["ledgers"]["positive"]["sha256"] == sha(ledgers["positive"].read_bytes())
    assert result["input_pins"]["implementation_sha256"]["scripts/precision_triage.py"] == sha(
        Path("scripts/precision_triage.py").read_bytes())
    frozen = output.read_bytes()
    with pytest.raises(FileExistsError):
        main()
    assert output.read_bytes() == frozen
