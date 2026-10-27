import copy
import hashlib
import json

import pytest

from scripts.label_review import consensus, prepare


@pytest.fixture
def packet(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    raw = b"// label should be hidden\npragma solidity ^0.8.20;\ncontract Example {}\n"
    (project / "Case.sol").write_bytes(raw)
    (project / "Dependency.sol").write_bytes(b"// dependency comment\nlibrary Dependency {}\n")
    cases = [{"id": "original-case", "project_path": str(project), "group": "audit",
              "target_file": "Case.sol", "target_contract": "Example", "vulnerability_class": "reentrancy",
              "ground_truth": "vulnerable", "source_sha256": hashlib.sha256(raw).hexdigest(),
              "provenance": {"original_assessment": "preserve", "project_files_sha256": {
                  name: hashlib.sha256((project / name).read_bytes()).hexdigest() for name in ("Case.sol", "Dependency.sol")}}}]
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"name": "unit", "cases": cases, "provenance": {"scanner_protocol": {"same": "code"}}}))
    output = tmp_path / "packet"
    prepare(manifest, output)
    return manifest, output, project


def submissions(packet, decisions=("clean", "clean")):
    _, directory, _ = packet
    paths = []
    for name, decision in zip(("a", "b"), decisions, strict=True):
        path = directory / "blind" / f"reviewer-{name}.json"
        doc = json.loads(path.read_text())
        doc["reviewer"] = {"id": f"unit-reviewer-{name}", "kind": "human", "qualification": "Unit test declaration",
                           "independence_declared": True}
        doc["reviews"][0].update(decision=decision, rationale="Unit test rationale", evidence_lines=[3])
        path.write_text(json.dumps(doc))
        paths.append(path)
    return paths


def test_blinded_packet_preserves_lines_and_context_without_labels(packet):
    manifest, directory, _ = packet
    doc = json.loads((directory / "blind/cases.json").read_text())
    row = doc["cases"][0]
    source = (directory / "blind" / row["source"]).read_text()
    assert "label should be hidden" not in source
    assert source.splitlines()[2] == "contract Example {}"
    assert "ground_truth" not in json.dumps(doc)
    assert "original-case" not in json.dumps(doc)
    assert len(row["context_files"]) == 2
    assert (directory / "original-manifest.json").read_bytes() == manifest.read_bytes()
    with pytest.raises(ValueError, match="already exists"):
        prepare(manifest, directory)


@pytest.mark.parametrize("decisions,truth,status", [
    (("clean", "clean"), "clean", "agreed"),
    (("vulnerable", "vulnerable"), "vulnerable", "agreed"),
    (("clean", "vulnerable"), "unknown", "unresolved"),
    (("unknown", "unknown"), "unknown", "unresolved"),
    (("pending", "clean"), "unknown", "pending"),
])
def test_consensus_never_rewrites_original_and_keeps_disagreements_unknown(packet, tmp_path, decisions, truth, status):
    manifest, directory, _ = packet
    original = manifest.read_bytes()
    a, b = submissions(packet, decisions)
    path = consensus(directory, a, b, tmp_path / "reviewed")
    doc = json.loads(path.read_text())
    assert doc["cases"][0]["ground_truth"] == truth
    review = doc["cases"][0]["provenance"]["human_review"]
    assert review["prior_ground_truth"] == "vulnerable"
    assert review["status"] == status
    assert manifest.read_bytes() == original
    assert doc["cases"][0]["provenance"]["original_assessment"] == "preserve"
    with pytest.raises(ValueError, match="already exists"):
        consensus(directory, a, b, path.parent)


@pytest.mark.parametrize("mode", ["pending_credentials", "same_reviewer", "model", "missing", "duplicate", "hash",
                                  "rationale", "line", "boolean_line", "empty_evidence", "decision"])
def test_invalid_reviews_fail_closed(packet, tmp_path, mode):
    _, directory, _ = packet
    a, b = submissions(packet)
    doc = json.loads(b.read_text())
    if mode == "pending_credentials":
        doc["reviewer"]["independence_declared"] = False
    elif mode == "same_reviewer":
        doc["reviewer"]["id"] = " UNIT-REVIEWER-A "
    elif mode == "model":
        doc["reviewer"]["kind"] = "model"
    elif mode == "missing":
        doc["reviews"] = []
    elif mode == "duplicate":
        doc["reviews"].append(copy.deepcopy(doc["reviews"][0]))
    elif mode == "hash":
        doc["packet_sha256"] = "b" * 64
    elif mode == "rationale":
        doc["reviews"][0]["rationale"] = ""
    elif mode == "line":
        doc["reviews"][0]["evidence_lines"] = [999]
    elif mode == "boolean_line":
        doc["reviews"][0]["evidence_lines"] = [True]
    elif mode == "empty_evidence":
        doc["reviews"][0]["evidence_lines"] = []
    else:
        doc["reviews"][0]["decision"] = "safe"
    b.write_text(json.dumps(doc))
    with pytest.raises(ValueError):
        consensus(directory, a, b, tmp_path / "invalid")
    assert not (tmp_path / "invalid").exists()


@pytest.mark.parametrize("mode", ["original", "dependency", "blind", "scope", "context"])
def test_changed_sources_or_blinded_scope_cannot_be_adjudicated(packet, tmp_path, mode):
    _, directory, project = packet
    a, b = submissions(packet)
    cases_path = directory / "blind/cases.json"
    cases = json.loads(cases_path.read_text())
    row = cases["cases"][0]
    if mode == "original":
        (project / "Case.sol").write_text("changed")
    elif mode == "dependency":
        (project / "Dependency.sol").write_text("changed")
    elif mode == "blind":
        (directory / "blind" / row["source"]).write_text("changed")
    elif mode == "context":
        (directory / "blind" / row["context_files"][0]["source"]).write_text("changed")
    else:
        row["target_contract"] = "Other"
        cases_path.write_text(json.dumps(cases))
    with pytest.raises(ValueError):
        consensus(directory, a, b, tmp_path / "invalid")


def test_scope_instructions_are_pinned_and_can_describe_uncompiled_context(packet, tmp_path):
    manifest, _, _ = packet
    document = json.loads(manifest.read_text())
    document["provenance"]["review_scope"] = "Uncompiled model input. Missing context means unknown."
    manifest.write_text(json.dumps(document))
    directory = tmp_path / "custom-packet"
    prepare(manifest, directory)
    cases_path = directory / "blind/cases.json"
    cases = json.loads(cases_path.read_text())
    assert cases["scope"] == document["provenance"]["review_scope"]
    a, b = submissions((manifest, directory, None))
    consensus(directory, a, b, tmp_path / "custom-reviewed")
    cases["scope"] = "Pretend all dependencies have been verified."
    cases_path.write_text(json.dumps(cases))
    with pytest.raises(ValueError, match="instructions"):
        consensus(directory, a, b, tmp_path / "tampered-reviewed")


@pytest.mark.parametrize("scope", ["", "   ", None, []])
def test_invalid_review_scope_fails_before_output(packet, tmp_path, scope):
    manifest, _, _ = packet
    document = json.loads(manifest.read_text())
    document["provenance"]["review_scope"] = scope
    manifest.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="scope"):
        prepare(manifest, tmp_path / "invalid-scope")
    assert not (tmp_path / "invalid-scope").exists()
