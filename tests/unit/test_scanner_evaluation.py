import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from sentinel.analyzers.parsers import parse_slither
from sentinel.analyzers.tools import project_compiler
from sentinel.evaluation import prepare_scanner_validation, qualification_gate
from sentinel.experiments import ExperimentManifest, run_experiment
from sentinel.modeling.data import strip_comments
from sentinel.modeling.properties import CGT_REVISION
from sentinel.schemas.analysis import AnalyzerRun
from sentinel.schemas.execution import ExecutionResult
from sentinel.schemas.state import RuntimeState
from sentinel.schemas.vulnerability import VulnerabilityFinding


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def case(**changes):
    return {"id": "sample", "project_path": ".", "group": "development",
            "vulnerability_class": "reentrancy", "ground_truth": "vulnerable", **changes}


def evaluate(tmp_path, cases, findings=(), error=False, profile="slither"):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"name": "unit", "cases": cases}))

    def scan(project, **kwargs):
        if error and kwargs["output"].name == "sample":
            raise RuntimeError("scanner crashed")
        return RuntimeState(project_path=str(project), enabled_analyzers=kwargs["enabled_analyzers"],
                            findings=list(findings), analyzer_runs=[
                                AnalyzerRun(tool=tool, target=".", status="completed")
                                for tool in kwargs["enabled_analyzers"]])

    return run_experiment(manifest, tmp_path / "reports", profile, scan=scan)


@pytest.mark.parametrize("node", [False, True])
def test_slither_uses_primary_nested_contract_not_unrelated_element(tmp_path, node):
    contract = {"type": "contract", "name": "Assessed"}
    primary = {"type": "function", "name": "withdraw", "type_specific_fields": {"parent": contract}}
    if node:
        primary = {"type": "node", "type_specific_fields": {"parent": primary}}
    raw = {"success": True, "results": {"detectors": [{"check": "reentrancy-eth", "description": "signal",
            "elements": [primary, {"type": "contract", "name": "Unrelated"}]}]}}
    assert parse_slither(json.dumps(raw), tmp_path)[0].contract == "Assessed"


def test_explicit_compiler_wins_and_missing_compiler_fails(tmp_path):
    compiler = tmp_path / "solc"
    compiler.write_bytes(b"compiler")
    assert project_compiler(tmp_path, {"solc": "./solc"}, Path("/fallback")) == compiler
    with pytest.raises(ValueError, match="unavailable"):
        project_compiler(tmp_path, {"solc": "./missing"}, None)


def test_supported_labels_are_profile_specific(tmp_path):
    report = evaluate(tmp_path, [case(vulnerability_class="arithmetic")])
    assert report["metric_scope"]["unsupported_labeled_cases"] == 1
    assert report["metrics"]["evaluated"] == 0
    assert evaluate(tmp_path, [case(vulnerability_class="arithmetic")], profile="mythril")["metrics"]["evaluated"] == 1


@pytest.mark.parametrize("contract,file,complete,detected", [
    ("Other", "src/Case.sol", True, False),
    ("Assessed", "src/Case.sol", True, True),
    ("", "src/Case.sol", False, False),
    ("Assessed", "", False, False),
])
def test_case_attribution(tmp_path, contract, file, complete, detected):
    finding = VulnerabilityFinding(id="signal", source="slither", detector="reentrancy-eth",
                                   description="candidate", contract=contract, file=file)
    report = evaluate(tmp_path, [case(target_contract="Assessed", target_file="src/Case.sol")], [finding])
    assert report["cases"][0]["coverage_complete"] is complete
    assert report["cases"][0]["detected"] is detected
    assert report["by_vulnerability_class"]["reentrancy"]["metrics"]["precision"] is None


def test_source_pin_failure_preserved_and_other_cases_continue(tmp_path):
    source = tmp_path / "Case.sol"
    source.write_bytes(b"changed")
    report = evaluate(tmp_path, [case(target_file="Case.sol", source_sha256=digest(b"original")), case(id="other")])
    assert "frozen assessment" in report["cases"][0]["error"]
    assert report["metrics"]["evaluated"] == 1
    assert not report["qualification"]["passed"]


def test_source_config_cannot_exclude_pinned_target(tmp_path):
    source = tmp_path / "Case.sol"
    source.write_bytes(b"contract Case {}")
    (tmp_path / "foundry.toml").write_text('[profile.default]\nsrc = "empty"\n')
    report = evaluate(tmp_path, [case(target_file="Case.sol", source_sha256=digest(source.read_bytes()))])
    assert "excluded" in report["cases"][0]["error"]
    assert report["metrics"]["evaluated"] == 0


@pytest.mark.parametrize("changed", ["binary", "configuration"])
def test_compiler_pin_checks_binary_and_configuration(tmp_path, changed):
    (tmp_path / "src").mkdir()
    (tmp_path / "src/Case.sol").write_text("pragma solidity ^0.8.20; contract Case {}")
    compiler = tmp_path / "solc"
    compiler.write_bytes(b"changed" if changed == "binary" else b"original")
    configured = str(compiler) if changed == "binary" else "./missing"
    (tmp_path / "foundry.toml").write_text(f'[profile.default]\nsolc = {json.dumps(configured)}\n')
    report = evaluate(tmp_path, [case(provenance={"compiler": {"path": str(compiler), "sha256": digest(b"original")}})])
    assert report["cases"][0]["error"]
    assert report["metrics"]["evaluated"] == 0


def test_scanner_exception_preserved_without_aborting_run(tmp_path):
    report = evaluate(tmp_path, [case(), case(id="other")], error=True)
    assert report["cases"][0]["error"] == "RuntimeError: scanner crashed"
    assert report["cases"][1]["coverage_complete"]


@pytest.mark.parametrize("cases", [[case(id="../escape")], [case(), case()], [case(target_file="../Case.sol")]])
def test_invalid_manifest_rejected(cases):
    with pytest.raises(ValidationError):
        ExperimentManifest.model_validate({"name": "unit", "cases": cases})


def gate_report(tp=20, fp=0, fn=0, tn=20):
    return {"cases": [{"source_sha256": "a" * 64}],
            "metric_scope": {"incomplete_labeled_cases": 0, "unsupported_labeled_cases": 0},
            "by_vulnerability_class": {"reentrancy": {"metrics": {
                "true_positives": tp, "false_positives": fp, "false_negatives": fn,
                "true_negatives": tn, "recall": tp / (tp + fn) if tp + fn else None}}}}


def test_qualification_needs_samples_coverage_and_accuracy():
    assert qualification_gate(gate_report())["passed"]
    assert not qualification_gate(gate_report(tp=2, tn=2))["passed"]
    assert not qualification_gate(gate_report(tp=10, fn=10))["passed"]
    assert not qualification_gate(gate_report(fp=10, tn=10))["passed"]
    report = gate_report()
    report["metric_scope"]["incomplete_labeled_cases"] = 1
    assert not qualification_gate(report)["passed"]
    report["metric_scope"]["incomplete_labeled_cases"] = 0
    report["cases"] = []
    assert not qualification_gate(report)["passed"]


@pytest.mark.parametrize("mode", ["mock", "partial", "profile", "drift"])
def test_frozen_comparison_rejects_protocol_changes_before_scanning(tmp_path, monkeypatch, mode):
    manifest = tmp_path / "manifest.json"
    protocol = {"profiles": ["slither", "sentinel-static"]}
    manifest.write_text(json.dumps({"name": "frozen", "cases": [case()],
                                    "provenance": {"scanner_protocol": protocol}}))

    def verify(*args):
        if mode == "drift":
            raise ValueError("runtime differs from frozen comparison")

    def forbidden_scan(*args, **kwargs):
        pytest.fail("Invalid frozen protocols must not launch scans")

    monkeypatch.setattr("sentinel.experiments.verify_scanner_protocol", verify)
    with pytest.raises(ValueError, match="frozen|Frozen"):
        run_experiment(manifest, tmp_path / "reports", "mythril" if mode == "profile" else "slither",
                       mock=mode == "mock", limit=1 if mode == "partial" else None, scan=forbidden_scan)


def test_runtime_drift_during_frozen_run_is_preserved_as_incomplete_case(tmp_path, monkeypatch):
    manifest = tmp_path / "manifest.json"
    protocol = {"profiles": ["slither", "sentinel-static"]}
    manifest.write_text(json.dumps({"name": "frozen", "cases": [case(), case(id="next")],
                                    "provenance": {"scanner_protocol": protocol}}))
    checks = 0

    def verify(*args):
        nonlocal checks
        checks += 1
        if checks == 3:
            raise ValueError("runtime differs from frozen comparison")

    def scan(project, **kwargs):
        return RuntimeState(project_path=str(project), enabled_analyzers=kwargs["enabled_analyzers"],
                            analyzer_runs=[AnalyzerRun(tool="slither", target=".", status="completed")])

    monkeypatch.setattr("sentinel.experiments.verify_scanner_protocol", verify)
    report = run_experiment(manifest, tmp_path / "reports", "slither", scan=scan)
    assert report["cases"][0]["coverage_complete"]
    assert report["cases"][1]["error"] == "ValueError: runtime differs from frozen comparison"
    assert report["metric_scope"]["incomplete_labeled_cases"] == 1
    assert not report["qualification"]["passed"]


@pytest.mark.parametrize("multiple", [False, True])
@pytest.mark.parametrize("candidate_split", ["train", "valid"])
def test_builder_excludes_fitted_groups_and_never_opens_test(tmp_path, monkeypatch, multiple, candidate_split):
    corpus, prepared, fitted = (tmp_path / name for name in ("corpus", "prepared", "fitted"))
    for directory in (corpus, prepared, fitted):
        directory.mkdir()
    rows = []
    for swc in ("104", "107", "115"):
        for vulnerable in (True, False):
            name = f"C{swc}{int(vulnerable)}"
            source = f"// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20; contract {name} {{}}"
            (corpus / f"{name}.sol").write_text(source)
            rows.append({"id": name, "swc": swc, "contract": name, "source_path": f"{name}.sol",
                         "source_hash": digest(strip_comments(source).encode()), "source_url": "https://example.test/source",
                         "project_group": name, "assessments": [],
                         "messages": [{"content": json.dumps({"swc": swc, "vulnerable": vulnerable})}]})
    used = {**rows[0], "id": "used", "project_group": "fitted"}
    valid = prepared / f"{candidate_split}.jsonl"
    valid.write_text("\n".join(json.dumps(row) for row in [used, *rows]))
    (prepared / "manifest.json").write_text(json.dumps({"source_revision": CGT_REVISION,
                                                       "split_sha256": {candidate_split: digest(valid.read_bytes())}}))
    for name in ("train", "valid"):
        (fitted / f"{name}.jsonl").write_text(json.dumps({"project_group": "fitted"}))
    monkeypatch.setattr("sentinel.evaluation.subprocess.run", lambda *a, **k: SimpleNamespace(stdout=CGT_REVISION))
    original = Path.open

    def guarded(path, *args, **kwargs):
        assert path.name != "test.jsonl", "Reserved test data must not be opened"
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded)
    compiler = tmp_path / "solc"
    compiler.write_bytes(b"compiler")

    class Compiler:
        def run(self, command, cwd):
            if "--version" in command:
                stdout = "solc 0.8.20"
            else:
                name = (cwd / "Case.sol").read_text().split("contract ")[1].split()[0]
                contracts = {f"Case.sol:{name}": {"bin": "1234"}}
                if multiple:
                    contracts["Case.sol:Companion"] = {"bin": "5678"}
                stdout = json.dumps({"contracts": contracts})
            return ExecutionResult(command=command, cwd=str(cwd), exit_code=0, success=True, stdout=stdout)

    output = tmp_path / "evaluation"
    path = prepare_scanner_validation(corpus, prepared, fitted, output, [compiler], per_bucket=1,
                                      runner=Compiler(), allow_multiple_contracts=multiple, candidate_split=candidate_split)
    manifest = json.loads(path.read_text())
    assert len(manifest["cases"]) == 6
    assert not manifest["provenance"]["missing_buckets"]
    assert manifest["provenance"]["allow_multiple_contracts"] is multiple
    assert manifest["provenance"]["candidate_split"] == candidate_split
    assert manifest["provenance"]["candidate_split_sha256"] == digest(valid.read_bytes())
    assert manifest["provenance"]["skipped"]["model_training_or_validation_component"] == 1
    assert {row["ground_truth"] for row in manifest["cases"]} == {"vulnerable", "clean"}
    for row in manifest["cases"]:
        assert digest((output / row["project_path"] / row["target_file"]).read_bytes()) == row["source_sha256"]
    exclusions = tmp_path / "previous.json"
    # A different component ID must not evade an exact-source exclusion.
    exclusions.write_text(json.dumps({"cases": [manifest["cases"][0],
        {**manifest["cases"][1], "provenance": {"clone_component": "different-group"}}]}))
    replica = prepare_scanner_validation(corpus, prepared, fitted, tmp_path / "replica", [compiler], per_bucket=1,
                                        runner=Compiler(), allow_multiple_contracts=multiple, candidate_split=candidate_split,
                                        exclude_manifests=[exclusions], frozen_protocol={"test": "snapshot"})
    replica_doc = json.loads(replica.read_text())
    assert len(replica_doc["cases"]) == 4
    assert replica_doc["provenance"]["skipped"]["prior_scanner_evaluation_component"] == 1
    assert replica_doc["provenance"]["skipped"]["prior_scanner_evaluation_source"] == 1
    assert len(replica_doc["provenance"]["missing_buckets"]) == 2
    assert replica_doc["provenance"]["excluded_evaluations"][0]["sha256"] == digest(exclusions.read_bytes())
    assert replica_doc["provenance"]["scanner_protocol"] == {"test": "snapshot"}
    assert not replica_doc["provenance"]["reserved_test_accessed"]
    for invalid in ({"candidate_split": "test"}, {"frozen_protocol": {"test": "snapshot"}}):
        with pytest.raises(ValueError, match="sealed|exclusions"):
            prepare_scanner_validation(corpus, prepared, fitted, tmp_path / "invalid", [compiler], **invalid)
    exclusions.write_text(json.dumps({"cases": [{"source_sha256": "malformed"}]}))
    with pytest.raises(ValueError, match="component and source hash"):
        prepare_scanner_validation(corpus, prepared, fitted, tmp_path / "malformed", [compiler],
                                   candidate_split=candidate_split, exclude_manifests=[exclusions])
    with pytest.raises(ValueError, match="already exists"):
        prepare_scanner_validation(corpus, prepared, fitted, output, [compiler], runner=Compiler())
    if multiple:
        with pytest.raises(ValueError, match="No eligible"):
            prepare_scanner_validation(corpus, prepared, fitted, tmp_path / "strict", [compiler], runner=Compiler(),
                                       candidate_split=candidate_split)
