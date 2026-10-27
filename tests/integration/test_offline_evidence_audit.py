from pathlib import Path

import pytest

from scripts import verification_audit as audit


def test_real_offline_evidence_audit(tmp_path):
    forge = Path.home() / ".foundry/bin/forge"
    solc = Path.home() / ".solc-select/artifacts/solc-0.8.20/solc-0.8.20"
    if not forge.is_file() or not solc.is_file():
        pytest.skip("Requires installed Forge and local solc 0.8.20; no mock substitution")
    output = tmp_path / "audit"
    report = audit.run(output, forge, solc)
    assert report["audit_passed"], [(r["case_id"], r["error"]) for r in report["cases"]]
    assert report["cases_passed"] == report["cases_planned"] == 4
    assert report["controls_rejected"] == report["controls_planned"] == 20
    assert report["inputs_unchanged"] and report["tools_unchanged"]
    assert report["precision"] is None and report["recall"] is None
    assert not report["precision_target_met"] and not report["model_or_detector_promoted"]
    for row in report["cases"]:
        assert row["security_transition"] and row["functional_passed"]
        assert all(control["rejected_for_expected_reason"] for control in row["controls"])
        for name, expected in row["artifact_sha256"].items():
            assert audit.digest(output / "artifacts" / row["case_id"] / name) == expected
    with pytest.raises(FileExistsError):
        audit.run(output, forge, solc)
