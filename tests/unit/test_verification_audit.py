import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import verification_audit as audit
from sentinel.foundry.runner import FoundryRunner
from sentinel.schemas.execution import ExecutionResult


def result(status="Success", name="testSecurity()", code=0, **kwargs):
    stdout = json.dumps({"test/Security.t.sol:SecurityTest": {"test_results": {name: {"status": status}}}})
    return ExecutionResult(command=["forge", "test"], cwd="fixture", stdout=stdout,
                           exit_code=code, success=code == 0, **kwargs)


def test_security_transition_requires_executed_failure_then_success():
    assert audit.security_transition(result("Failure", code=1), result())


@pytest.mark.parametrize("before,after", [
    (result(), result()),
    (result("Skipped", code=1), result()),
    (result("Failure", name="setUp()", code=1), result()),
    (result("Failure", code=1, timed_out=True), result()),
    (result("Failure", code=1), result("Skipped")),
    (result("Failure", name="testOther()", code=1), result()),
    (ExecutionResult(command=[], cwd="fixture", exit_code=1, stdout="compile error"), result()),
    (ExecutionResult(command=[], cwd="fixture", exit_code=1, stdout="{}"), result()),
])
def test_no_security_confirmation_from_missing_or_nonexecuted_tests(before, after):
    assert not audit.security_transition(before, after)


def test_security_transition_requires_identical_test_identity():
    after = result()
    after.stdout = after.stdout.replace("SecurityTest", "DifferentTest")
    assert not audit.security_transition(result("Failure", code=1), after)


@pytest.fixture
def runner(tmp_path):
    log = tmp_path / "logs"
    log.mkdir()
    return audit.OfflineRunner(Path("/pinned/forge"), Path("/pinned/solc"), tmp_path / "home", log)


def test_runner_clears_credentials_and_pins_offline_command(runner, tmp_path, monkeypatch):
    captured = {}

    def execute(command, **kwargs):
        captured.update(command=command, **kwargs)
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")

    monkeypatch.setenv("ETH_RPC_URL", "sensitive")
    monkeypatch.setenv("PRIVATE_KEY", "sensitive")
    monkeypatch.setenv("FOUNDRY_FFI", "true")
    monkeypatch.setattr(audit.subprocess, "run", execute)
    command = ["forge", "test", "--json", "--match-test", FoundryRunner._selector("testSecurity"),
               "--use", "/pinned/solc"]
    execution = runner.run(command, tmp_path)
    assert execution.success
    assert captured["command"][-3:] == ["--offline", "--threads", "1"]
    assert captured["command"][0] == "/pinned/forge"
    assert set(captured["env"]) == {"HOME", "PATH", "RAYON_NUM_THREADS", "FOUNDRY_DISABLE_NIGHTLY_WARNING"}
    saved = json.loads((runner.log / "0001.json").read_text())
    assert saved["command"] == captured["command"]


@pytest.mark.parametrize("command", [
    ["cast", "send"], ["forge", "script"], ["forge", "test"],
    ["forge", "test", "--json", "--use", "/other/solc"],
    ["forge", "test", "--json", "--fork-url", "https://example.test"],
    ["forge", "test", "--json", "--ffi"],
    ["forge", "test", "--match-test", ".*"],
    ["forge", "test", "--match-path", "../test/Escape.t.sol"],
    ["forge", "test", "--match-path", "/test/Escape.t.sol"],
    ["forge", "test", "--match-path", ""],
    ["forge", "test", "--json", "--json"],
    ["forge", "build", "--match-test", "testSecurity"],
])
def test_runner_rejects_network_unpinned_and_broad_commands(runner, tmp_path, command):
    with pytest.raises(ValueError):
        runner.run(command, tmp_path)
    assert not list(runner.log.iterdir())


def test_runner_rejects_env_override_and_unpinned_version(runner, tmp_path):
    with pytest.raises(ValueError):
        runner.run(["forge", "build"], tmp_path, env={"PRIVATE_KEY": "no"})
    with pytest.raises(ValueError):
        runner.version(Path("/other/solc"), tmp_path)


def test_runner_retains_timeout_evidence(runner, tmp_path, monkeypatch):
    def timeout(*args, **kwargs):
        raise audit.subprocess.TimeoutExpired(args[0], 60, output=b"partial", stderr=b"incomplete")

    monkeypatch.setattr(audit.subprocess, "run", timeout)
    execution = runner.run(["forge", "build", "--use", "/pinned/solc"], tmp_path)
    assert execution.timed_out and not execution.success
    assert execution.stdout == "partial" and execution.stderr == "incomplete"
    assert (runner.log / "0001.json").is_file()


def test_project_copy_excludes_credentials_and_build_artifacts(tmp_path):
    source, destination = tmp_path / "source", tmp_path / "copy"
    (source / "src").mkdir(parents=True)
    (source / "out").mkdir()
    (source / ".env").write_text("secret")
    (source / "out/Build.sol").write_text("cached")
    (source / "src/Source.sol").write_text("contract Source {}")
    (source / "foundry.toml").write_text("[profile.default]")
    audit.copy_project(source, destination)
    assert sorted(p.relative_to(destination).as_posix() for p in destination.rglob("*") if p.is_file()) == [
        "foundry.toml", "src/Source.sol"]


def test_json_outputs_are_exclusive(tmp_path):
    path = tmp_path / "report.json"
    audit.write_json(path, {"precision": None})
    with pytest.raises(FileExistsError):
        audit.write_json(path, {"precision": 1})
    assert json.loads(path.read_text()) == {"precision": None}


def test_pending_external_does_not_convert_unknown_to_clean(tmp_path):
    path = tmp_path / "external.json"
    case = {"case_id": "external", "target_contract": "Target", "source_sha256": "pinned",
            "ground_truth": "unknown", "matched_finding_ids": ["candidate-1"], "unmatched_findings": 3}
    path.write_text(json.dumps({"cases": [case]}))
    pending = audit.pending_external(path)
    assert pending[0]["ground_truth"] == "unknown"
    assert pending[0]["matched_finding_ids"] == ["candidate-1"]
    assert pending[0]["unmatched_findings"] == 3
    assert not pending[0]["confirmed_by_this_audit"]
    path.write_text(json.dumps({"cases": [case, case]}))
    with pytest.raises(ValueError, match="Duplicate external case"):
        audit.pending_external(path)


def test_missing_tool_does_not_create_a_success_report(tmp_path):
    with pytest.raises(ValueError, match="Installed Forge"):
        audit.run(tmp_path / "output", tmp_path / "missing-forge", tmp_path / "missing-solc")
    assert not (tmp_path / "output").exists()
