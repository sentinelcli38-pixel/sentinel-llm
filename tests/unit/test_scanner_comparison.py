import copy
import hashlib
import json

import pytest

from scripts.compare_scanner_profiles import compare, main, metrics


def reports():
    cases = [{"id": name, "project_path": ".", "group": "development", "vulnerability_class": "reentrancy",
              "ground_truth": truth, "target_contract": "Example", "target_file": "src/Case.sol",
              "source_sha256": "a" * 64, "provenance": {"assessment": name}}
             for name, truth in (("positive", "vulnerable"), ("negative", "clean"))]
    provenance = {"scanner_protocol": {"frozen": "same"}}
    manifest = json.dumps({"name": "fresh", "cases": cases, "provenance": provenance}).encode()
    rows = [{**{k: v for k, v in case.items() if k not in ("id", "project_path")}, "case_id": case["id"],
             "detected": False, "coverage_complete": True, "attribution_complete": True,
             "label_supported": True, "error": None} for case in cases]
    base = {"profile": {"name": "slither"}, "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
            "dataset_provenance": provenance, "cases": rows, "metrics": metrics(rows),
            "qualification": {"passed": False, "reasons": ["insufficient samples"]}}
    extended = copy.deepcopy(base)
    extended["profile"]["name"] = "sentinel-static"
    extended["cases"][0]["detected"] = True
    extended["metrics"] = metrics(extended["cases"])
    return manifest, base, extended


def test_comparison_recomputes_metrics_and_preserves_failed_gates():
    manifest, baseline, extended = reports()
    result = compare(manifest, baseline, extended)
    assert result["baseline"]["true_positives"] == 0
    assert result["extended"]["true_positives"] == 1
    assert result["by_vulnerability_class"]["reentrancy"]["extended"]["false_positives"] == 0
    assert [row["case_id"] for row in result["changed_predictions"]] == ["positive"]
    assert not result["qualification"]["extended"]["passed"]


@pytest.mark.parametrize("mode", ["manifest", "profile", "provenance", "missing", "duplicate", "label", "source", "scope",
                                  "coverage", "attribution", "error", "unsupported", "prediction", "metrics"])
def test_mismatched_or_incomplete_runs_cannot_enter_comparison(mode):
    manifest, baseline, extended = reports()
    row = extended["cases"][0]
    if mode == "manifest":
        extended["manifest_sha256"] = "b" * 64
    elif mode == "profile":
        extended["profile"]["name"] = "slither"
    elif mode == "provenance":
        extended["dataset_provenance"] = {}
    elif mode == "missing":
        extended["cases"].pop()
    elif mode == "duplicate":
        extended["cases"].append(copy.deepcopy(row))
    elif mode == "label":
        row["ground_truth"] = "clean"
    elif mode == "source":
        row["source_sha256"] = "b" * 64
    elif mode == "scope":
        row["target_contract"] = "Other"
    elif mode == "coverage":
        row["coverage_complete"] = False
    elif mode == "attribution":
        row["attribution_complete"] = False
    elif mode == "error":
        row["error"] = "scanner failed"
    elif mode == "unsupported":
        row["label_supported"] = False
    elif mode == "prediction":
        row["detected"] = "true"
    else:
        extended["metrics"]["true_positives"] = 99
    with pytest.raises(ValueError):
        compare(manifest, baseline, extended)


def test_false_positive_changes_are_not_hidden():
    manifest, baseline, extended = reports()
    extended["cases"][1]["detected"] = True
    extended["metrics"] = metrics(extended["cases"])
    result = compare(manifest, baseline, extended)
    assert result["extended"]["false_positives"] == 1
    assert result["changed_predictions"][1]["ground_truth"] == "clean"


def test_unfrozen_inputs_are_rejected():
    manifest, baseline, extended = reports()
    document = json.loads(manifest)
    document["provenance"] = {}
    with pytest.raises(ValueError, match="frozen"):
        compare(json.dumps(document).encode(), baseline, extended)


def test_cli_pins_exact_input_reports_and_refuses_overwrite(tmp_path, monkeypatch):
    manifest, baseline, extended = reports()
    manifest_path = tmp_path / "manifest.json"
    baseline_path = tmp_path / "baseline.json"
    extended_path = tmp_path / "extended.json"
    output_path = tmp_path / "comparison.json"
    manifest_path.write_bytes(manifest)
    baseline_bytes = json.dumps(baseline, indent=2).encode()
    extended_bytes = json.dumps(extended, indent=2).encode()
    baseline_path.write_bytes(baseline_bytes)
    extended_path.write_bytes(extended_bytes)
    monkeypatch.setattr("sys.argv", ["compare", "--manifest", str(manifest_path), "--baseline", str(baseline_path),
                                     "--extended", str(extended_path), "--output", str(output_path)])
    main()
    result = json.loads(output_path.read_text())
    assert result["report_pins"]["baseline"]["sha256"] == hashlib.sha256(baseline_bytes).hexdigest()
    assert result["report_pins"]["extended"]["sha256"] == hashlib.sha256(extended_bytes).hexdigest()
    frozen = output_path.read_bytes()
    with pytest.raises(FileExistsError):
        main()
    assert output_path.read_bytes() == frozen
