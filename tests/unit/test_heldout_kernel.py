import json
import math

import pytest

from sentinel.modeling.properties import property_messages
from training import heldout_kernel as hk


def row(key, truth, swc="101", source=None):
    contract = f"Case_{key}"
    source = source or f"contract {contract} {{ function f() public returns(uint) {{ return 1; }} }}"
    return {"id": key, "swc": swc, "task": "swc_property", "contract": contract,
            "source_hash": hk.gp.sha(source.encode()), "project_group": key, "lexical_fingerprint": f"fixture-{key}",
            "messages": [*property_messages(source, swc, contract),
                         {"role": "assistant", "content": json.dumps({"swc": swc, "vulnerable": truth})}]}


def cohort():
    rows, folds = [], {}
    for fold in range(3):
        for swc in hk.gp.PROPERTIES:
            for truth in (False, True):
                item = row(f"r_{fold}_{swc}_{truth}", truth, swc)
                rows.append(item)
                folds[item["id"]] = fold
    return rows, folds


def test_partition_keeps_every_training_row_in_exactly_one_role_and_all_labels():
    rows, folds = cohort()
    fit, threshold = hk.partition(rows, folds)
    assert len(fit) == 16 and len(threshold) == 8
    assert {r["id"] for r in fit}.isdisjoint({r["id"] for r in threshold})
    assert {r["id"] for r in fit + threshold} == {r["id"] for r in rows}
    assert all(folds[r["id"]] == 2 for r in threshold)


@pytest.mark.parametrize("identity", ["project_group", "source_hash", "lexical_fingerprint"])
def test_overlap_between_model_fit_and_threshold_roles_is_rejected(identity):
    rows, folds = cohort()
    rows[-1][identity] = rows[0][identity]
    with pytest.raises(ValueError, match="Fold overlap"):
        hk.partition(rows, folds)


def test_audit_distinguishes_lossy_feature_collisions_from_exact_input_contradictions():
    rows = [row("a", True), row("b", False)]
    audit = hk.training_audit(rows)
    assert audit["results"]["exact_source_target"]["mixed_groups"] == []
    assert audit["results"]["normalized_whole_source"]["mixed_rows"] == 2
    assert audit["rows_without_explicit_compiler_or_dependency_lock"] == 2
    assert hk.gp.source_and_target(rows[0])[1]["vulnerable"] is True


def test_bounded_scores_are_stable_at_float_ties_and_do_not_invert_orientation():
    values = hk.scores_from_margins([-100.0, -1.0, 0.0, 1.0, 100.0])
    assert values == sorted(values)
    assert values[0] == 0 and values[-1] == 1 and values[2] == 0.5
    assert hk.scores_from_margins([1.0, math.nextafter(1.0, 0.0)])[0] == values[3]


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf, True, "1"])
def test_invalid_margins_are_failures(value):
    with pytest.raises(ValueError, match="Finite"):
        hk.scores_from_margins([value])


def test_support_audit_distinguishes_observed_precision_from_the_existing_interval_rule():
    rows = [row(f"p_{swc}_{i}", True, swc) for swc in hk.gp.PROPERTIES for i in range(3)]
    result = hk.best_case_support(rows)
    assert result["minimum_perfect_positive_flags_for_existing_nominal_rule"] == 381
    assert result["scopes"]["overall"]["available_positives"] == 12
    assert not result["scopes"]["overall"]["existing_99_interval_rule_possible"]
    assert result["scopes"]["overall"]["additional_zero_false_positive_flags_for_nominal_rule"] == 369
    large = hk.best_case_support([row(f"p_{i}", True) for i in range(381)])
    assert large["scopes"]["overall"]["existing_99_interval_rule_possible"]


def test_fixed_small_catalog_and_recall_floor():
    candidates = hk.catalog()
    assert len(candidates) == len({c["id"] for c in candidates}) == 4
    assert {c["C"] for c in candidates} == {1.0, 10.0}
    assert hk.PLAN["minimum_recall"] == 0.8 and hk.PLAN["target_precision"] == 0.99


def test_cli_requires_experimental_acknowledgement(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.argv", ["heldout_kernel.py", "fit", "--output", str(tmp_path)])
    with pytest.raises(SystemExit) as error:
        hk.main()
    assert error.value.code == 2
