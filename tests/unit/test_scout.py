import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from sentinel.agents.scout import Scout
from sentinel.analyzers.parsers import (
    parse_mythril,
    parse_slither,
    rank_and_deduplicate,
)
from sentinel.analyzers.tools import project_sources, run_scout_tools
from sentinel.graph.workflow import build_workflow
from sentinel.llm.mock import MockProvider
from sentinel.runner import ControlledRunner
from sentinel.schemas.execution import ExecutionResult
from sentinel.schemas.state import RuntimeState


@pytest.fixture
def project(tmp_path):
    (tmp_path / "foundry.toml").write_text('[profile.default]\nsrc="src"\nsolc_version="0.8.20"\nremappings=["lib/=vendor/"]\n')
    (tmp_path / "src" / "nested").mkdir(parents=True)
    (tmp_path / "src" / "nested" / "Vault.sol").write_text("contract Vault {}")
    return tmp_path


def slither_payload():
    return {"success": True, "results": {"detectors": [{
        "check": "reentrancy-eth", "impact": "High", "confidence": "Medium",
        "description": "Vault.withdraw writes state after an external call",
        "elements": [{"type": "function", "name": "withdraw", "source_mapping": {
            "filename_relative": "src/nested/Vault.sol", "lines": [12, 13]}}],
    }]}}


def mythril_payload():
    return {"success": True, "issues": [{
        "swc-id": "107", "title": "External Call To User-Supplied Address",
        "description": "A call is made to an address supplied by the caller",
        "severity": "Medium", "filename": "src/nested/Vault.sol", "lineno": 12,
        "contract": "Vault", "function": "withdraw()", "address": 123,
        "tx_sequence": {"steps": []},
    }]}


class AnalyzerRunner:
    def __init__(self, slither=None, mythril=None):
        self.slither = slither if slither is not None else slither_payload()
        self.mythril = mythril if mythril is not None else mythril_payload()
        self.commands = []
        self.solc_settings = None

    def run(self, command, cwd, env=None):
        self.commands.append(list(command))
        self.env = env
        if command[0] == "myth":
            self.solc_settings = json.loads(Path(command[command.index("--solc-json") + 1]).read_text())
        payload = self.slither if command[0] == "slither" else self.mythril
        return ExecutionResult(command=list(command), cwd=str(cwd), exit_code=1,
                               success=False, stdout=json.dumps(payload))


def test_slither_normalizes_nonzero_finding_output(project):
    bundle = run_scout_tools(project, AnalyzerRunner())
    assert [r.status for r in bundle.runs] == ["completed", "completed"]
    assert len(bundle.findings) == 2
    finding = bundle.findings[0]
    assert (finding.source, finding.severity, finding.confidence_score) == ("slither", "high", 0.6)
    assert (finding.file, finding.line, finding.function) == ("src/nested/Vault.sol", 12, "withdraw")
    assert all(f.status == "candidate" for f in bundle.findings)


def test_analyzer_selection_supports_single_tool_baselines(project):
    runner = AnalyzerRunner()
    bundle = run_scout_tools(project, runner, enabled_analyzers={"slither"})

    assert [run.tool for run in bundle.runs] == ["slither"]
    assert [command[0] for command in runner.commands] == ["slither"]


def test_mythril_preserves_swc_and_transaction_evidence(project):
    finding = parse_mythril(json.dumps(mythril_payload()), project)[0]
    assert finding.detector == "SWC-107"
    assert finding.confidence == "unknown"
    assert '"tx_sequence"' in finding.raw_output


def test_empty_success_does_not_create_fake_findings(project):
    runner = AnalyzerRunner({"success": True, "results": {}}, {"success": True, "issues": []})
    bundle = run_scout_tools(project, runner)
    assert not bundle.findings
    assert all(r.status == "completed" for r in bundle.runs)


def test_slither_vendored_dependency_findings_are_excluded_from_project_audit(project):
    payload = slither_payload()
    payload["results"]["detectors"].append({
        "check": "incorrect-exp", "impact": "High", "confidence": "High",
        "description": "Vendored math implementation uses a deliberate xor operation",
        "elements": [{"type": "function", "name": "mulDiv", "source_mapping": {
            "filename_relative": "lib/vendor/Math.sol", "lines": [9],
        }}],
    })
    bundle = run_scout_tools(project, AnalyzerRunner(slither=payload))
    assert [finding.file for finding in bundle.findings] == ["src/nested/Vault.sol", "src/nested/Vault.sol"]


def test_slither_unlocated_evidence_is_not_silently_discarded(project):
    payload = slither_payload()
    payload["results"]["detectors"][0]["elements"] = []
    bundle = run_scout_tools(project, AnalyzerRunner(slither=payload), enabled_analyzers={"slither"})
    assert len(bundle.findings) == 1
    assert bundle.findings[0].file == ""


@pytest.mark.parametrize("raw", ['not json', '[]', '{"success":false}', '{"success":true,"issues":{}}'])
def test_invalid_mythril_output_rejected(project, raw):
    with pytest.raises((ValueError, TypeError)):
        parse_mythril(raw, project)


def test_partial_tool_failure_keeps_other_findings(project):
    bundle = run_scout_tools(project, AnalyzerRunner(mythril={"success": False, "error": "compiler error"}))
    assert [r.status for r in bundle.runs] == ["completed", "failed"]
    assert len(bundle.findings) == 1


def test_structured_analyzer_failure_is_not_classified_as_invalid_json(project):
    runner = AnalyzerRunner(mythril={"success": False, "error": "compiler unavailable"})
    runner.mythril = {"success": False, "error": "compiler unavailable"}
    bundle = run_scout_tools(project, runner)
    assert bundle.runs[1].status == "failed"
    assert bundle.runs[1].diagnostics == ["compiler unavailable"]


def test_mythril_commands_are_local_bounded_and_remapped(project):
    runner = AnalyzerRunner()
    run_scout_tools(project, runner, mythril_timeout=17, transaction_count=3)
    command = runner.commands[1]
    assert command[:3] == ["myth", "analyze", str(project / "src/nested/Vault.sol")]
    assert "--no-onchain-data" in command
    assert command[command.index("--execution-timeout") + 1] == "17"
    assert command[command.index("--transaction-count") + 1] == "3"
    assert command[command.index("--solv") + 1] == "0.8.20"
    assert runner.solc_settings["remappings"] == ["lib/=vendor/"]
    assert not Path(command[command.index("--solc-json") + 1]).exists()


def test_explicit_compiler_path_is_passed_only_to_mythril(project, tmp_path):
    compiler = tmp_path / "solc"
    compiler.write_text("binary")
    runner = AnalyzerRunner()
    run_scout_tools(project, runner, solc_binary=compiler)
    assert "--solv" not in runner.commands[1]
    assert runner.env and runner.env["SOLC"] == str(compiler.resolve())
    assert "MYTHRIL_DIR" in runner.env


def test_missing_tools_are_reported_without_normal_mode_heuristics(project):
    with patch("sentinel.runner.subprocess.run", side_effect=FileNotFoundError("not installed")):
        bundle = run_scout_tools(project, ControlledRunner())
    assert not bundle.findings
    assert bundle.runs[0].status == "unavailable"
    assert bundle.runs[1].status == "unavailable"


def test_timeout_with_partial_json_is_not_a_completed_scan(project):
    error = subprocess.TimeoutExpired(["myth"], 1, output=b'{"success":true}', stderr=b'timed out\xff')
    with patch("sentinel.runner.subprocess.run", side_effect=error):
        bundle = run_scout_tools(project, ControlledRunner())
    assert not bundle.findings
    assert all(r.status == "timed_out" for r in bundle.runs)
    assert isinstance(bundle.runs[0].execution.stderr, str)


def test_duplicates_ranked_without_merging_different_tools(project):
    slither = parse_slither(json.dumps(slither_payload()), project)[0]
    mythril = parse_mythril(json.dumps(mythril_payload()), project)[0]
    assert rank_and_deduplicate([mythril, slither, slither]) == [slither, mythril]


def test_scout_passes_real_evidence_to_provider(project):
    class RecordingProvider(MockProvider):
        def generate(self, prompt):
            assert "reentrancy-eth" in prompt and "SWC-107" in prompt
            return super().generate(prompt)
    state = Scout(RecordingProvider(), AnalyzerRunner()).analyze(RuntimeState(project_path=str(project)))
    assert len(state.analyzer_runs) == 2
    assert state.mythril_results
    assert state.candidate_id == state.findings[0].id
    assert not state.exploit_confirmed


def test_scout_only_does_not_call_the_llm_provider(project):
    class FailingProvider(MockProvider):
        def generate(self, prompt):
            raise AssertionError("Scout-only must not call an LLM")
    state = Scout(FailingProvider(), AnalyzerRunner()).analyze(
        RuntimeState(project_path=str(project), scout_only=True)
    )
    assert state.findings
    assert not state.scout_results


def test_workflow_scout_only_does_not_write_sources_or_run_exploits(project):
    runner = AnalyzerRunner()
    result = build_workflow(runner).invoke(RuntimeState(project_path=str(project), mock_mode=True, scout_only=True))
    assert result["final_verification_state"] == "scout_incomplete"
    assert not (project / "test").exists()
    assert not any(c[0] == "forge" for c in runner.commands)
    assert (project / "src/nested/Vault.sol").read_text() == "contract Vault {}"


def test_workflow_accepts_intentionally_bounded_mythril_sampling(project):
    for index in range(10):
        (project / "src" / f"Source{index}.sol").write_text(f"contract Source{index} {{}}")
    runner = AnalyzerRunner()
    result = build_workflow(runner).invoke(RuntimeState(project_path=str(project), mock_mode=True, scout_only=True))
    assert result["final_verification_state"] == "scout_incomplete"
    assert result["analyzer_runs"][-1].status == "skipped"


def test_real_findings_do_not_claim_verification_without_a_confirmed_poc(project):
    result = build_workflow(AnalyzerRunner()).invoke(RuntimeState(project_path=str(project), mock_mode=True))
    assert result["final_verification_state"] in {"finding_discarded", "human_review_required"}
    assert not result["exploit_confirmed"]


def test_absolute_external_paths_not_used_as_patch_targets(project):
    data = mythril_payload()
    data["issues"][0]["filename"] = "/etc/passwd"
    assert parse_mythril(json.dumps(data), project)[0].file == ""


def test_symlink_outside_project_rejected(project, tmp_path):
    (project / "src" / "escape.sol").symlink_to("/etc/passwd")
    with pytest.raises(ValueError, match="symlink"):
        project_sources(project)


def test_custom_source_directory(project):
    (project / "foundry.toml").write_text('[profile.default]\nsrc="contracts"\n')
    (project / "contracts").mkdir()
    (project / "contracts" / "C.sol").write_text("contract C {}")
    assert [p.name for p in project_sources(project)[0]] == ["C.sol"]


def test_invalid_project_stops_before_tools(tmp_path):
    runner = AnalyzerRunner()
    result = build_workflow(runner).invoke(RuntimeState(project_path=str(tmp_path)))
    assert result["final_verification_state"] == "invalid_project"
    assert not runner.commands


def test_cli_incomplete_scan_writes_honest_json(project, tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from sentinel.cli import app

    def missing(*args, **kwargs):
        raise FileNotFoundError("tools unavailable")
    monkeypatch.setattr("sentinel.runner.subprocess.run", missing)
    output = tmp_path / "reports"
    result = CliRunner().invoke(app, ["scan", str(project), "--scout-only", "--mock", "--output", str(output)])
    assert result.exit_code == 2
    assert "scout_incomplete" in result.output
    assert next(output.glob("*.md")).is_file()
    ledger = json.loads(next(path for path in output.glob("*.json") if not path.name.endswith("__summary.json")).read_text())
    assert ledger["final_verification_state"] == "scout_incomplete"
    assert not ledger["exploit_confirmed"]
    assert ledger["analyzer_runs"][0]["status"] == "unavailable"


def test_provider_failure_keeps_findings(project):
    class UnavailableProvider(MockProvider):
        def generate(self, prompt):
            raise RuntimeError("provider unavailable")
    state = Scout(UnavailableProvider(), AnalyzerRunner()).analyze(RuntimeState(project_path=str(project)))
    assert len(state.findings) == 2
    assert any("provider unavailable" in message for message in state.feedback)


def test_normal_mode_does_not_invent_heuristic_findings(project):
    (project / "src/nested/Vault.sol").write_text('contract Vault { function f() external { msg.sender.call{value: 1}(""); balances[msg.sender] = 0; } }')
    runner = AnalyzerRunner({"success": True, "results": {}}, {"success": True, "issues": []})
    assert not run_scout_tools(project, runner).findings
    assert run_scout_tools(project, runner, demo_fallback=True).findings[0].source == "local-heuristic"
