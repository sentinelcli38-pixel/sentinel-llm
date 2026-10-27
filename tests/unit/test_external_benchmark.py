import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import external_benchmark as module
from sentinel.schemas.analysis import AnalyzerRun
from sentinel.schemas.execution import ExecutionResult
from sentinel.schemas.state import RuntimeState


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    corpus, fitted, cgt, smartbugs = (tmp_path / name for name in ("external", "fit", "cgt", "smartbugs"))
    for path in (corpus, fitted, cgt, smartbugs / "dataset"):
        path.mkdir(parents=True)
    prior = "pragma solidity ^0.8.20; contract Prior {uint total; function f(uint x) external {total += x;}}"
    (smartbugs / "dataset/Prior.sol").write_text(prior)
    for split in ("train", "valid"):
        (fitted / f"{split}.jsonl").write_text("")
    project = corpus / "project/contracts"
    project.mkdir(parents=True)
    source = ('pragma solidity ^0.8.20; contract Example {mapping(address=>uint) balances; '
              'function withdraw() external {uint v=balances[msg.sender]; (bool ok,)=msg.sender.call{value:v}(""); '
              'require(ok); balances[msg.sender]=0;}}')
    (project / "External.sol").write_text(source)
    (project / "Dependency.sol").write_text("library Dependency {function zero() internal pure returns(uint){return 0;}}")
    (corpus / "vfp.json").write_text(json.dumps({"findings": [{"id": 2, "title": "Audit assertion",
        "files": ["contracts/External.sol"]}], "affected_files": {"External.sol": source}}))
    (corpus / "audit.json").write_text(json.dumps({"path": "reports/audit.pdf", "project_info": {"commit_id": "upstream"}}))
    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps({"repository": "https://example.test/external", "revision": "PIN", "cases": [
        {"id": "external-case", "project_root": "project", "source_root": "contracts", "target_file": "contracts/External.sol",
         "target_contract": "Example", "vulnerability_class": "reentrancy", "vfp": "vfp.json",
         "metadata": "audit.json", "finding_id": 2}]}))
    prior_project = tmp_path / "prior"
    prior_project.mkdir()
    (prior_project / "Prior.sol").write_text(prior)
    exclude = tmp_path / "exclude.json"
    exclude.write_text(json.dumps({"name": "prior", "cases": [{"id": "prior", "project_path": str(prior_project),
        "group": "development", "target_file": "Prior.sol", "target_contract": "Prior",
        "source_sha256": hashlib.sha256(prior.encode()).hexdigest()}]}))
    compiler = tmp_path / "solc-0.8.20"
    compiler.write_text("compiler fixture")
    original_run = module.subprocess.run

    def pinned_git(command, *args, **kwargs):
        if command[0] == "git":
            return SimpleNamespace(stdout="PIN")
        return original_run(command, *args, **kwargs)

    monkeypatch.setattr(module.subprocess, "run", pinned_git)
    monkeypatch.setattr(module, "git_bytes", lambda root, revision, name: (root / name).read_bytes())
    return {"registry": registry, "corpus": corpus, "output": tmp_path / "prepared", "compilers": [compiler],
            "smartbugs": smartbugs, "fitted": fitted, "cgt": cgt, "exclusions": [exclude],
            "protocol": {"profiles": ["slither", "sentinel-static"]}}


class Compiler:
    def __init__(self, success=True, malformed=False):
        self.success, self.malformed = success, malformed

    def run(self, command, cwd):
        version = "--version" in command
        stdout = "solc 0.8.20" if version else "not JSON" if self.malformed else json.dumps({
            "contracts": {"contracts/External.sol:Example": {"bin": "bytecode"}},
            "sourceList": ["contracts/External.sol", "contracts/Dependency.sol"]})
        return ExecutionResult(command=command, cwd=str(cwd), success=version or self.success,
                               exit_code=0 if version or self.success else 1, stdout=stdout,
                               stderr="" if version or self.success else "missing dependency")


def test_external_preparation_keeps_labels_unknown_and_never_opens_sealed_test(inputs, monkeypatch):
    original = Path.open

    def guarded(path, *args, **kwargs):
        assert path.name != "test.jsonl", "Reserved model test must stay sealed"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded)
    manifest_path = module.prepare(**inputs, runner=Compiler())
    doc = json.loads(manifest_path.read_text())
    case = doc["cases"][0]
    assert case["ground_truth"] == "unknown"
    assert case["provenance"]["label_status"] == "pending_human_review"
    assert case["provenance"]["annotation"]["finding"]["title"] == "Audit assertion"
    assert doc["provenance"]["reserved_test_accessed"] is False
    project = manifest_path.parent / case["project_path"]
    module.verify_project(project, case["provenance"]["project_files_sha256"])
    (project / "out/External.sol").mkdir(parents=True)
    module.verify_project(project, case["provenance"]["project_files_sha256"])
    with pytest.raises(ValueError, match="already exists"):
        module.prepare(**inputs, runner=Compiler())


@pytest.mark.parametrize("mode", ["compile", "malformed", "overlap"])
def test_unrunnable_cases_are_preserved_not_stubbed_or_scored(inputs, mode):
    if mode == "overlap":
        external = (inputs["corpus"] / "project/contracts/External.sol").read_text()
        (inputs["smartbugs"] / "dataset/Overlap.sol").write_text(external)
    with pytest.raises(ValueError, match="No runnable"):
        module.prepare(**inputs, runner=Compiler(success=mode != "compile", malformed=mode == "malformed"))
    doc = json.loads((inputs["output"] / "readiness.json").read_text())
    assert doc["candidates"][0]["status"] == "blocked"
    assert not (inputs["output"] / "manifest.json").exists()
    if mode == "compile":
        assert "missing dependency" in doc["candidates"][0]["attempts"][0]["stderr"]


@pytest.mark.parametrize("change", ["dependency", "inventory", "configuration"])
def test_dependency_and_configuration_drift_prevents_scanning(inputs, monkeypatch, tmp_path, change):
    manifest_path = module.prepare(**inputs, runner=Compiler())
    doc = json.loads(manifest_path.read_text())
    project = manifest_path.parent / doc["cases"][0]["project_path"]
    name = {"dependency": "contracts/Dependency.sol", "inventory": "contracts/Extra.sol",
            "configuration": "foundry.toml"}[change]
    (project / name).write_text("changed")
    monkeypatch.setattr("sentinel.experiments.verify_scanner_protocol", lambda *args: None)

    def forbidden(*args, **kwargs):
        pytest.fail("Changed context must not launch a scan")

    report = module.run(manifest_path, tmp_path / "reports", "slither", scan=forbidden)
    assert report["coverage_complete_cases"] == 0
    assert report["cases"][0]["error"]
    assert not report["qualification"]["passed"]


def test_unlabelled_external_run_cannot_claim_accuracy(inputs, monkeypatch, tmp_path):
    manifest_path = module.prepare(**inputs, runner=Compiler())
    monkeypatch.setattr("sentinel.experiments.verify_scanner_protocol", lambda *args: None)

    def completed(project, **kwargs):
        return RuntimeState(project_path=str(project), enabled_analyzers=kwargs["enabled_analyzers"],
                            analyzer_runs=[AnalyzerRun(tool="slither", target=".", status="completed")])

    report = module.run(manifest_path, tmp_path / "reports", "slither", scan=completed)
    assert report["coverage_complete_cases"] == 1
    assert report["unlabeled_cases"] == 1
    assert report["metrics"]["evaluated"] == 0
    assert report["metrics"]["recall"] is None
    assert not report["qualification"]["passed"]


def test_workflow_drift_is_rejected_before_run(inputs, tmp_path):
    manifest_path = module.prepare(**inputs, runner=Compiler())
    doc = json.loads(manifest_path.read_text())
    doc["provenance"]["workflow_sha256"] = "changed"
    manifest_path.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="workflow differs"):
        module.run(manifest_path, tmp_path / "reports", "slither")


def test_only_native_target_dependency_closure_is_copied(inputs):
    unrelated = inputs["corpus"] / "project/contracts/Unrelated.sol"
    unrelated.write_text("contract Unrelated {}")
    path = module.prepare(**inputs, runner=Compiler())
    doc = json.loads(path.read_text())
    case = doc["cases"][0]
    assert case["provenance"]["omitted_non_dependency_sources"] == ["contracts/Unrelated.sol"]
    assert not (path.parent / case["project_path"] / "contracts/Unrelated.sol").exists()
    assert unrelated.exists()
