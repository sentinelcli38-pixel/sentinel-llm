import json
from pathlib import Path

from sentinel.experiments import run_experiment
from sentinel.schemas.analysis import AnalyzerRun
from sentinel.schemas.state import RuntimeState
from sentinel.schemas.vulnerability import VulnerabilityFinding


def test_experiment_metrics_ignore_unlabeled_cases(tmp_path: Path) -> None:
    manifest = tmp_path / "experiment.json"
    manifest.write_text(json.dumps({"name": "unit", "cases": [
        {"id": "vuln", "project_path": "vuln", "group": "held_out", "vulnerability_class": "reentrancy", "ground_truth": "vulnerable"},
        {"id": "clean", "project_path": "clean", "group": "clean", "vulnerability_class": "clean", "ground_truth": "clean"},
        {"id": "unknown", "project_path": "unknown", "group": "audit", "ground_truth": "unknown"},
    ]}), encoding="utf-8")

    def fake_scan(project: Path, **kwargs) -> RuntimeState:
        findings = [] if project.name == "clean" else [VulnerabilityFinding(
            id=project.name, source="slither", detector="reentrancy-eth", description="candidate",
        )]
        return RuntimeState(
            project_path=str(project), findings=findings, final_report_path=str(kwargs["output"] / "report.md"),
            enabled_analyzers=["slither"],
            analyzer_runs=[AnalyzerRun(tool="slither", target=".", status="completed")],
        )

    report = run_experiment(manifest, tmp_path / "reports", "slither", scan=fake_scan)

    assert report["metrics"]["precision"] == 1.0
    assert report["metrics"]["recall"] == 1.0
    assert report["unlabeled_cases"] == 1
    assert report["profile"]["enabled_analyzers"] == ["slither"]


def test_experiment_excludes_incomplete_cases_and_masks_metrics_without_clean_controls(tmp_path: Path) -> None:
    manifest = tmp_path / "experiment.json"
    manifest.write_text(json.dumps({"name": "unit", "cases": [
        {"id": "unavailable", "project_path": "unavailable", "group": "held_out", "ground_truth": "vulnerable"},
    ]}), encoding="utf-8")

    def incomplete_scan(project: Path, **kwargs) -> RuntimeState:
        return RuntimeState(
            project_path=str(project),
            analyzer_runs=[AnalyzerRun(tool="slither", target=".", status="failed")],
        )

    report = run_experiment(manifest, tmp_path / "reports", "slither", scan=incomplete_scan)

    assert report["metrics"]["evaluated"] == 0
    assert report["metrics"]["precision"] is None
    assert report["metrics"]["recall"] is None
    assert report["metric_scope"]["incomplete_labeled_cases"] == 1


def test_experiment_rejects_unknown_profile(tmp_path: Path) -> None:
    manifest = tmp_path / "experiment.json"
    manifest.write_text('{"name":"unit","cases":[{"id":"x","project_path":".","group":"fixture"}]}', encoding="utf-8")
    try:
        run_experiment(manifest, tmp_path / "reports", "not-a-profile")
    except ValueError as exc:
        assert "Unknown experiment profile" in str(exc)
    else:
        raise AssertionError("Unknown profile must be rejected")
