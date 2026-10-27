import json
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sentinel.agents.judge import Judge
from sentinel.cli import app
from sentinel.coverage import coverage_complete
from sentinel.experiments import run_experiment
from sentinel.foundry.evidence import passed
from sentinel.foundry.evidence import test_results as parse_tests
from sentinel.policy import evaluate_policy
from sentinel.reporting.markdown import write_report
from sentinel.schemas.analysis import AnalyzerRun
from sentinel.schemas.execution import ExecutionResult
from sentinel.schemas.state import RuntimeState
from sentinel.schemas.vulnerability import VulnerabilityFinding
from sentinel.service import run_scan


@pytest.mark.parametrize("code,stdout,timeout", [
    (0, "{}", False), (0, "", False), (1, "Compiler run failed", False),
    (-1, "{}", False), (0, "{}", True),
    (1, '{"test/X.t.sol:X":{"test_results":{"setUp()":{"status":"Failure"}}}}', False),
    (0, '{"test/X.t.sol:X":{"test_results":{"testX()":{"status":"Skipped"}}}}', False),
    (0, '{"test/X.t.sol:X":{"test_results":{"testX()":{"status":"Unexpected"}}}}', False),
])
def test_unexecuted_or_invalid_tests_never_pass(code, stdout, timeout):
    result = ExecutionResult(command=["forge"], cwd="/tmp", exit_code=code, stdout=stdout, timed_out=timeout)
    assert not passed(result)


def test_judge_accepts_complete_unchanged_test_evidence(repair_state, repair_foundry):
    result = Judge(repair_foundry).verify(repair_state)
    assert result.final_verification_state == "verified"
    assert result.judge_result.verified


@pytest.mark.parametrize("field", ["baseline_exploit_result", "baseline_regression_result", "exploit_artifact", "oracle_test_hashes", "patch_diff"])
def test_judge_rejects_missing_evidence(repair_state, repair_foundry, field):
    setattr(repair_state, field, {} if field == "oracle_test_hashes" else "" if field == "patch_diff" else None)
    result = Judge(repair_foundry).verify(repair_state)
    assert not result.judge_result.verified
    assert result.final_verification_state == "human_review_required"


@pytest.mark.parametrize("stdout,code", [("{}", 0), ("{}", 1), ("compiler error", 1)])
def test_judge_rejects_generic_forge_errors(repair_state, repair_foundry, stdout, code):
    repair_foundry.exploit_override = ExecutionResult(command=["forge"], cwd="/tmp", exit_code=code, stdout=stdout)
    result = Judge(repair_foundry).verify(repair_state)
    assert not result.judge_result.verified
    assert not result.judge_result.exploit_neutralized


def test_judge_rejects_changed_oracle(repair_state, repair_foundry):
    Path(repair_state.exploit_artifact.test_file).write_text("contract Empty {}")
    assert not Judge(repair_foundry).verify(repair_state).judge_result.verified


def test_judge_rejects_removed_regression(repair_state, repair_foundry):
    repair_foundry.regression_override = repair_state.baseline_regression_result.model_copy(update={"stdout": "{}"})
    result = Judge(repair_foundry).verify(repair_state)
    assert not result.judge_result.regression_passed
    assert not result.judge_result.verified


def test_judge_rejects_different_regression_identities(repair_state, repair_foundry):
    repair_foundry.regression_override = repair_state.baseline_regression_result.model_copy(update={
        "stdout": repair_state.baseline_regression_result.stdout.replace("testDepositAndWithdraw", "testUnrelated")})
    assert not Judge(repair_foundry).verify(repair_state).judge_result.verified


def test_named_validation_requires_a_matching_executed_test(repair_state, repair_foundry):
    (Path(repair_state.project_path) / "sentinel-validation.yml").write_text("positive_tests: [testGood]\n")
    repair_foundry.named_test = lambda *args: repair_state.baseline_regression_result
    result = Judge(repair_foundry).verify(repair_state)
    assert result.judge_result.positive_tests_passed is False
    assert not result.judge_result.verified


def test_coverage_requires_every_enabled_tool_and_no_skips():
    state = RuntimeState(project_path="/project", analyzer_runs=[AnalyzerRun(tool="slither", target=".", status="completed")])
    assert not coverage_complete(state)
    state.enabled_analyzers = ["slither"]
    assert coverage_complete(state)
    state.analyzer_runs.append(AnalyzerRun(tool="slither", target="ignored.sol", status="skipped"))
    assert not coverage_complete(state)
    assert evaluate_policy(state, {}).status == "blocked"


@pytest.mark.parametrize("policy", [{"block_severity": "hgh"}, {"require_complete_coverage": "false"}, {"ignore_all": True}])
def test_policy_rejects_misconfiguration(policy):
    with pytest.raises(ValueError):
        evaluate_policy(RuntimeState(project_path="/project"), policy)


def test_empty_scan_never_passes_default_release_policy():
    assert evaluate_policy(RuntimeState(project_path="/project"), {}).status == "blocked"


def test_wrong_class_and_maintenance_warnings_do_not_count_as_detection(tmp_path):
    manifest = tmp_path / "experiment.json"
    manifest.write_text(json.dumps({"name": "matching", "cases": [
        {"id": "wrong", "project_path": ".", "group": "held_out", "ground_truth": "vulnerable", "vulnerability_class": "reentrancy"},
        {"id": "maintenance", "project_path": ".", "group": "clean", "ground_truth": "clean", "vulnerability_class": "clean"},
    ]}))

    def scan(project, **kwargs):
        detector = "tx-origin" if Path(kwargs["output"]).name == "wrong" else "solc-version"
        return RuntimeState(project_path=str(project), enabled_analyzers=["slither"],
                            analyzer_runs=[AnalyzerRun(tool="slither", target=".", status="completed")],
                            findings=[VulnerabilityFinding(id="warn", detector=detector, source="slither", description="warning")])

    report = run_experiment(manifest, tmp_path / "reports", "slither", scan=scan)
    assert report["metrics"]["false_negatives"] == 1
    assert report["metrics"]["false_positives"] == 0
    assert all(not row["detected"] for row in report["cases"])


def test_report_does_not_label_unverified_patch_as_verified(repair_state, tmp_path):
    write_report(repair_state, tmp_path / "reports")
    finding_report = next((tmp_path / "reports").glob("*__findings/*.md")).read_text()
    assert "Proposed, unverified patch artifact" in finding_report
    assert "Verified patch artifact" not in finding_report


def test_workspace_is_removed_when_workflow_raises(tmp_path, monkeypatch):
    project = tmp_path / "target"
    project.mkdir()
    (project / "foundry.toml").write_text('[profile.default]\nsrc="src"\n')
    (project / "src").mkdir()
    (project / "src/C.sol").write_text("contract C {}")
    owned = tmp_path / "sentinel-workspace-test"
    owned.mkdir()
    monkeypatch.setattr("sentinel.graph.workflow.tempfile.mkdtemp", lambda **kwargs: str(owned))
    monkeypatch.setattr("sentinel.graph.workflow.ControlledRunner.run", lambda *args: ExecutionResult.failed(["solc"], str(project), "unavailable"))

    def fail(*args):
        raise RuntimeError("unexpected scanner failure")

    monkeypatch.setattr("sentinel.graph.workflow.Scout.analyze", fail)
    with pytest.raises(RuntimeError, match="unexpected scanner"):
        run_scan(project)
    assert not owned.exists()
    assert (project / "src/C.sol").read_text() == "contract C {}"


def test_local_model_requires_explicit_research_opt_in():
    root = Path(__file__).parents[2]
    result = subprocess.run([sys.executable, "training/predict_mlx.py", "examples/vulnerable_reentrancy/src/VulnerableVault.sol"], cwd=root, capture_output=True, text=True, check=False)
    assert result.returncode != 0
    assert "research-only" in result.stderr


def test_parse_valid_test_json(repair_state):
    assert len(parse_tests(repair_state.baseline_exploit_result)) == 1


@pytest.mark.parametrize("outcome", ["human_review_required", "execution_unavailable", "analysis_incomplete", "invalid_project"])
def test_cli_inconclusive_scan_is_not_a_success(tmp_path, monkeypatch, outcome):
    monkeypatch.setattr("sentinel.cli.run_scan", lambda *args, **kwargs: RuntimeState(project_path=str(tmp_path), final_verification_state=outcome))
    result = CliRunner().invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 2
    assert outcome in result.stdout


def test_invalid_validation_profile_terminates_without_retry_loop(tmp_path, monkeypatch, repair_foundry):
    import shutil

    project = tmp_path / "target"
    shutil.copytree(Path(__file__).parents[2] / "examples/vulnerable_reentrancy", project)
    (project / "sentinel-validation.yml").write_text("positive_tests: ['testBad; shell']\n")
    monkeypatch.setattr("sentinel.graph.workflow.FoundryRunner", lambda runner: repair_foundry)
    monkeypatch.setattr("sentinel.graph.workflow.ControlledRunner.run", lambda *args: ExecutionResult.failed(["solc"], str(project), "unavailable"))

    def scout(self, state):
        state.candidate_id = "heuristic-reentrancy"
        state.findings = [VulnerabilityFinding(id=state.candidate_id, source="local-heuristic", detector="fixture", description="fixture", file="src/VulnerableVault.sol")]
        return state

    monkeypatch.setattr("sentinel.graph.workflow.Scout.analyze", scout)
    result = run_scan(project, output=tmp_path / "reports", mock=True)
    assert result.final_verification_state == "human_review_required"
    assert result.judge_result.failure_reason == "invalid validation profile"
    assert result.retry_count == 0
