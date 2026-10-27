import hashlib
import json

import pytest

from scripts.prepare_scanner_reanalysis import prepare


def test_reanalysis_preserves_original_protocol_and_labels_and_marks_reuse(tmp_path):
    original = tmp_path / "original.json"
    document = {"name": "frozen", "cases": [
        {"id": "case", "project_path": "project", "group": "held_out", "ground_truth": "vulnerable",
         "target_file": "src/Case.sol", "target_contract": "Assessed", "source_sha256": "a" * 64,
         "vulnerability_class": "reentrancy", "provenance": {"compiler": {"sha256": "b" * 64}}}],
        "provenance": {"scanner_protocol": {"old": "implementation"}, "reserved_test_accessed": False}}
    original.write_text(json.dumps(document))
    frozen = original.read_bytes()
    path = prepare(original, tmp_path / "new", {"new": "implementation"})
    current = json.loads(path.read_text())
    assert original.read_bytes() == frozen
    assert current["provenance"]["original_manifest_sha256"] == hashlib.sha256(frozen).hexdigest()
    assert current["provenance"]["previous_scanner_protocol"] == document["provenance"]["scanner_protocol"]
    assert current["provenance"]["scanner_protocol"] == {"new": "implementation"}
    assert "Not independent validation" in current["provenance"]["analysis_scope"]
    assert current["cases"][0]["group"] == "development"
    assert current["cases"][0]["project_path"] == str(tmp_path / "project")
    for field in ("ground_truth", "target_file", "target_contract", "source_sha256", "vulnerability_class", "provenance"):
        assert current["cases"][0][field] == document["cases"][0][field]
    with pytest.raises(ValueError, match="already exists"):
        prepare(original, tmp_path / "new", {})


def test_unfrozen_evaluation_cannot_masquerade_as_frozen_reanalysis(tmp_path):
    original = tmp_path / "original.json"
    original.write_text(json.dumps({"name": "ordinary", "cases": [
        {"id": "case", "project_path": ".", "group": "development"}]}))
    with pytest.raises(ValueError, match="previously frozen"):
        prepare(original, tmp_path / "new", {})
