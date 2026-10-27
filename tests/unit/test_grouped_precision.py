import copy
import json
import math
from pathlib import Path

import pytest

from sentinel.modeling.properties import CGT_REVISION, PROPERTIES, property_messages
from training import grouped_precision as gp


def row(key, swc="104", truth=False, group=None):
    source = f"contract Case_{key} {{ function value() public pure returns(uint) {{ return 1; }} }}"
    return {"id": key, "swc": swc, "contract": f"Case_{key}", "task": "swc_property",
            "source_hash": gp.sha(source.encode()), "project_group": group or key,
            "lexical_fingerprint": f"synthetic-{key}",
            "messages": [*property_messages(source, swc, f"Case_{key}"),
                         {"role": "assistant", "content": json.dumps({"swc": swc, "vulnerable": truth})}]}


def cohort():
    rows, folds = [], {}
    for fold in range(3):
        for swc in PROPERTIES:
            for label in (False, True):
                r = row(f"r_{fold}_{swc}_{label}", swc, label)
                rows.append(r)
                folds[r["id"]] = fold
    return rows, folds


def test_training_reader_never_opens_validation_or_test(tmp_path, monkeypatch):
    rows, _ = cohort()
    raw = b"\n".join(json.dumps(r).encode() for r in rows)
    (tmp_path / "train.jsonl").write_bytes(raw)
    manifest = {"source_revision": CGT_REVISION, "task": "swc_property",
                "split_counts": {"train": len(rows), "valid": 99},
                "split_sha256": {"train": gp.sha(raw), "valid": "metadata-only"}}
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    original = Path.open

    def guard(path, *args, **kwargs):
        assert path.name not in {"valid.jsonl", "test.jsonl"}
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guard)
    loaded, pins = gp.read_training(tmp_path)
    assert loaded == rows
    assert pins["split_sha256"]["valid"] == "metadata-only"
    assert not pins["reserved_test_accessed"]
    (tmp_path / "train.jsonl").write_bytes(raw + b" ")
    with pytest.raises(ValueError, match="Training data changed"):
        gp.read_training(tmp_path)


@pytest.mark.parametrize("identity", ["project_group", "source_hash", "lexical_fingerprint"])
def test_every_group_and_source_family_stays_in_one_fold(identity):
    rows, folds = cohort()
    gp.check_folds(rows, folds)
    rows[-1][identity] = rows[0][identity]
    with pytest.raises(ValueError, match="Fold overlap"):
        gp.check_folds(rows, folds)


@pytest.mark.parametrize("mode", ["missing", "duplicate", "bool", "range", "missing_class"])
def test_invalid_fold_cohorts_abort_instead_of_dropping_cases(mode):
    rows, folds = cohort()
    if mode == "missing":
        folds.pop(rows[0]["id"])
    elif mode == "duplicate":
        rows.append(copy.deepcopy(rows[0]))
    elif mode == "bool":
        folds[rows[0]["id"]] = True
    elif mode == "range":
        folds[rows[0]["id"]] = 3
    else:
        rows[0]["messages"][-1]["content"] = json.dumps({"swc": rows[0]["swc"], "vulnerable": True})
    with pytest.raises(ValueError):
        gp.check_folds(rows, folds)


def test_threshold_selection_keeps_ties_together_and_checks_all_targets():
    selected = gp.choose_threshold([True, True, False, False], [2.0, 2.0, -1.0, -1.0])
    assert selected["point_target_feasible"]
    assert selected["tp"] == 2 and selected["fp"] == 0
    assert -1 < selected["threshold"] < 2
    assert selected["recall"] == 1


def test_impossible_target_has_explicit_fallback_and_does_not_sacrifice_recall():
    result = gp.choose_threshold([True, False, True, False], [3.0, 2.0, 1.0, 0.0])
    assert not result["point_target_feasible"]
    assert result["recall"] == 1
    assert result["tp"] == 2 and result["fp"] == 1
    assert result["precision"] == 2 / 3
    all_tied = gp.choose_threshold([True, False], [0.0, 0.0])
    assert all_tied["recall"] == 1 and all_tied["precision"] == 0.5
    assert not all_tied["point_target_feasible"]


@pytest.mark.parametrize("labels,margins", [([True], [1.0]), ([True, False], [1.0]),
    ([1, 0], [1.0, 0.0]), ([True, False], [math.nan, 0.0]),
    ([True, False], [math.inf, 0.0]), ([True, False], [True, 0.0]), ([], [])])
def test_threshold_selection_rejects_invalid_or_missing_assessments(labels, margins):
    with pytest.raises(ValueError):
        gp.choose_threshold(labels, margins)


def test_candidate_selection_prefers_feasible_then_recall_with_deterministic_ties():
    perfect = gp.choose_threshold([True, False], [1.0, -1.0])
    fallback = gp.choose_threshold([True, False], [0.0, 0.0])
    candidates = [{"id": "z", "selection": perfect}, {"id": "a", "selection": perfect},
                  {"id": "zero", "selection": fallback}]
    result = gp.select_candidate(candidates)
    assert result["candidate"] == "a"
    assert result["status"] == "training_point_targets_met"
    assert gp.select_candidate([candidates[-1]])["status"] == "failed_target_diagnostic_fallback"
    with pytest.raises(ValueError):
        gp.select_candidate([candidates[0], candidates[0]])


def test_catalog_is_fixed_bounded_and_contains_all_class_weight_and_regularization_controls():
    catalog = gp.catalog()
    assert len(catalog) == len({c["id"] for c in catalog}) == 12
    assert {c["representation"] for c in catalog} == {"tokens_1_3", "characters_3_5"}
    assert {c["class_weight"] for c in catalog} == {None, "balanced"}
    assert {c["C"] for c in catalog} == {0.1, 1.0, 10.0}


def test_missing_completed_fit_receipt_cannot_open_validation(tmp_path, monkeypatch):
    monkeypatch.setattr(gp, "load_training", lambda _: ({}, []))
    monkeypatch.setattr(gp, "read_development", lambda _: pytest.fail("Premature validation read"))
    with pytest.raises(FileNotFoundError):
        gp.evaluate_frozen(tmp_path)


def test_cli_requires_explicit_experimental_acknowledgement(monkeypatch, tmp_path):
    monkeypatch.setattr("sys.argv", ["grouped_precision.py", "fit", "--output", str(tmp_path)])
    with pytest.raises(SystemExit) as error:
        gp.main()
    assert error.value.code == 2
