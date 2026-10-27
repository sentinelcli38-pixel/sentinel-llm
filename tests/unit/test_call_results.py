import json

import pytest

from sentinel.analyzers.call_results import ResultStep, unused_results
from sentinel.analyzers.parsers import parse_sentinel_static
from sentinel.detection import finding_class
from sentinel.experiments import PROFILES


def test_assigned_but_unused_send_result_is_a_candidate():
    steps = [ResultStep("call", write="result"), ResultStep("copy", ("result",), "saved")]
    assert unused_results(steps) == [0]


def test_read_before_call_does_not_count_as_checking_later_ssa_value():
    steps = [ResultStep("use", ("success_0",)), ResultStep("call", write="tmp"),
             ResultStep("copy", ("tmp",), "success_1")]
    assert unused_results(steps) == [1]


@pytest.mark.parametrize("sink", ["condition", "return", "event", "storage", "unknown-operation"])
def test_any_non_copy_use_conservatively_suppresses_warning(sink):
    steps = [ResultStep("call", write="result"), ResultStep("copy", ("result",), "a"),
             ResultStep("copy", ("a",), "b"), ResultStep("use", ("b",), sink)]
    assert unused_results(steps) == []


def test_tuple_data_use_does_not_consume_success_result():
    steps = [ResultStep("call", write="tuple:0"), ResultStep("copy", ("tuple:1",), "data"),
             ResultStep("use", ("data",))]
    assert unused_results(steps) == [0]


def test_phi_cycles_terminate_and_do_not_manufacture_usage():
    steps = [ResultStep("call", write="result"), ResultStep("copy", ("result", "b"), "a"),
             ResultStep("copy", ("a",), "b")]
    assert unused_results(steps) == [0]


def test_multiple_calls_have_distinct_ssa_lifetimes():
    steps = [ResultStep("call", write="result_0"), ResultStep("call", write="result_1"),
             ResultStep("use", ("result_1",))]
    assert unused_results(steps) == [0]


def test_empty_and_void_results():
    assert unused_results([]) == []
    assert unused_results([ResultStep("call")]) == [0]


@pytest.mark.parametrize("detector,category", [("unused-call-result", "unchecked_low_level_calls"),
                                              ("origin-auth-alternative", "tx_origin")])
def test_experimental_output_is_not_claimed_as_vanilla_slither(tmp_path, detector, category):
    raw = {"success": True, "results": {"detectors": [{"check": detector,
            "description": "Dead result", "elements": []}]}}
    finding = parse_sentinel_static(json.dumps(raw), tmp_path)[0]
    assert finding.source == "sentinel-static"
    assert finding.id.startswith("sentinel-static-")
    assert finding_class(finding) == category
    assert PROFILES["slither"].enabled_analyzers == ["slither"]
    assert PROFILES["sentinel-static"].scout_only
    raw["results"]["detectors"][0]["check"] = "invented-detector"
    with pytest.raises(ValueError, match="Unexpected"):
        parse_sentinel_static(json.dumps(raw), tmp_path)


def test_static_paths_resolve_when_cli_runs_outside_the_project(tmp_path):
    raw = {"success": True, "results": {"detectors": [{"check": "unused-call-result", "description": "candidate",
           "elements": [{"type": "node", "source_mapping": {
               "filename_relative": "datasets/case/src/Case.sol", "filename_absolute": str(tmp_path / "src/Case.sol")}}]}]}}
    assert parse_sentinel_static(json.dumps(raw), tmp_path)[0].file == "src/Case.sol"


@pytest.mark.parametrize("change", ["none", "mismatch", "no_element", "missing", "bad_name"])
def test_inherited_static_findings_require_complete_context(tmp_path, change):
    fields = {"execution_contract": "Child", "declaring_contract": "Base",
              "attribution": "compiled-inherited-entry-point"}
    elements = [{"type": "function", "name": "withdraw", "type_specific_fields": {
        "parent": {"type": "contract", "name": "Base"}}}, {"type": "contract", "name": "Child"}]
    if change == "mismatch":
        fields["declaring_contract"] = "Sibling"
    elif change == "no_element":
        elements.pop()
    elif change == "missing":
        fields = {}
    elif change == "bad_name":
        fields["execution_contract"] = "../Child"
    item = {"check": "inherited-reentrancy-eth", "description": "candidate", "elements": elements,
            "additional_fields": fields}
    raw = json.dumps({"success": True, "results": {"detectors": [item]}})
    if change == "none":
        finding = parse_sentinel_static(raw, tmp_path)[0]
        assert finding.contract == "Child"
        assert finding_class(finding) == "reentrancy"
    else:
        with pytest.raises(ValueError, match="inheritance|execution context"):
            parse_sentinel_static(raw, tmp_path)
