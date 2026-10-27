import copy
import json

import pytest

from sentinel.modeling.properties import PROPERTIES, property_messages
from training.binary_mlx import source_and_target
from training.provisional_review import (
    APPROVAL,
    INPUTS,
    load,
    main,
    overlay,
    prepare,
    reconcile,
    sha,
)


def row(key, truth, swc="104"):
    source = f"contract Case_{key} {{\nfunction value() public pure returns(uint) {{ return 1; }}\n}}\n"
    return {"id": key, "swc": swc, "task": "swc_property", "contract": f"Case_{key}",
            "source_hash": sha(source.encode()), "project_group": key,
            "messages": [*property_messages(source, swc, f"Case_{key}"),
                         {"role": "assistant", "content": json.dumps({"swc": swc, "vulnerable": truth})}]}


def fixture_documents():
    reviewed = [row("clean", True), row("positive", True), row("unknown", False), row("conflict", False)]
    training = [*reviewed, *[row(f"train_{swc}_{truth}", truth, swc)
                           for swc in PROPERTIES if swc != "104" for truth in (False, True)]]
    valid = [row(f"valid_{swc}_{truth}", truth, swc) for swc in PROPERTIES for truth in (False, True)]
    cases = [{"id": r["id"], "target_contract": r["contract"], "source_sha256": r["source_hash"],
              "group": "development", "vulnerability_class": f"SWC-104: {PROPERTIES['104']}",
              "provenance": {"role": "training"}} for r in reviewed]
    manifest = json.dumps({"name": "unit-fixture-not-a-benchmark", "cases": cases}).encode()
    mapping, blind = {}, []
    for r in reviewed:
        review_id = "review-" + sha(f"{sha(manifest)}:{r['id']}".encode())[:16]
        mapping[review_id] = r["id"]
        blind.append({"review_id": review_id, "target_contract": r["contract"], "source_sha256": r["source_hash"],
                      "blind_source_sha256": r["source_hash"], "line_count": 3, "context_files": [],
                      "vulnerability_class": f"SWC-104: {PROPERTIES['104']}"})
    packet = json.dumps({"manifest_sha256": sha(manifest), "cases": blind}).encode()
    choices = {"a": ["clean", "vulnerable", "unknown", "vulnerable"],
               "b": ["clean", "vulnerable", "unknown", "clean"]}
    raws = {"packet": packet, "manifest": manifest, "mapping": json.dumps({"case_mapping": mapping}).encode()}
    for name in ("a", "b"):
        raws[name] = json.dumps({"packet_sha256": sha(packet), "manifest_sha256": sha(manifest),
            "reviewer": {"id": f"fixture-ai-{name}", "kind": "ai", "independence_declared": False},
            "reviews": [{"review_id": case["review_id"], "source_sha256": case["source_sha256"],
                         "decision": decision, "rationale": "Synthetic unit-test observation, not expert review.",
                         "evidence_lines": [1]} for case, decision in zip(blind, choices[name], strict=True)]}).encode()
    return raws, {"train": training, "valid": valid}


def test_reconciliation_preserves_full_denominator_and_pending_approval_provenance():
    raws, rows = fixture_documents()
    ledger = reconcile(raws, rows)
    assert ledger["coverage"] == 4
    assert ledger["eligible"] == 2
    assert ledger["withheld_from_training"] == 2
    assert ledger["status_counts"] == {"agreed_definite": 2, "both_unknown": 1, "unresolved": 1}
    assert ledger["label_changes_among_agreements"] == 1
    assert ledger["approval_report"]["status"] == "user_reported_approval_written_reports_pending"
    assert ledger["approval_report"]["written_reports"] == []
    assert not ledger["signed_human_consensus"]
    assert all(r["kind"] == "ai" for r in ledger["declared_reviewers"].values())


def test_overlay_is_training_only_does_not_mutate_sources_and_retains_index_alignment():
    raws, rows = fixture_documents()
    before = copy.deepcopy(rows)
    ledger = reconcile(raws, rows)
    selected, indices = overlay(rows["train"], ledger)
    assert len(selected) == 8
    assert indices == [0, 1, 4, 5, 6, 7, 8, 9]
    assert rows == before
    assert source_and_target(selected[0])[1]["vulnerable"] is False
    assert selected[0]["source_hash"] == before["train"][0]["source_hash"]
    assert rows["valid"] == before["valid"]
    assert {case["id"] for case in ledger["cases"] if case["provisional_label"] is None} == {"unknown", "conflict"}


@pytest.mark.parametrize("mode", ["header", "missing", "duplicate", "source", "rationale", "line", "bool_line", "decision", "identity", "same_identity"])
def test_invalid_review_observations_are_rejected_without_rewriting_identity(mode):
    raws, rows = fixture_documents()
    doc = json.loads(raws["b"])
    first = doc["reviews"][0]
    if mode == "header":
        doc["packet_sha256"] = "f" * 64
    elif mode == "missing":
        doc["reviews"].pop()
    elif mode == "duplicate":
        doc["reviews"][1] = first
    elif mode == "source":
        first["source_sha256"] = "f" * 64
    elif mode == "rationale":
        first["rationale"] = ""
    elif mode == "line":
        first["evidence_lines"] = [999]
    elif mode == "bool_line":
        first["evidence_lines"] = [True]
    elif mode == "decision":
        first["decision"] = "safe"
    elif mode == "identity":
        doc["reviewer"]["kind"] = "unattributed"
    else:
        doc["reviewer"]["id"] = json.loads(raws["a"])["reviewer"]["id"]
    raws["b"] = json.dumps(doc).encode()
    with pytest.raises(ValueError):
        reconcile(raws, rows)


def test_validation_cases_and_modified_sources_cannot_be_relabelled_by_training_reviews():
    raws, rows = fixture_documents()
    rows["train"][0]["swc"] = "107"
    with pytest.raises(ValueError):
        reconcile(raws, rows)
    raws, rows = fixture_documents()
    ledger = reconcile(raws, rows)
    with pytest.raises(ValueError):
        overlay(rows["valid"], ledger)
    changed = copy.deepcopy(ledger)
    changed["cases"][0]["source_sha256"] = "f" * 64
    with pytest.raises(ValueError):
        overlay(rows["train"], changed)


def test_pending_decisions_remain_unknown_and_ineligible():
    raws, rows = fixture_documents()
    document = json.loads(raws["b"])
    document["reviews"][1].update(decision="pending", rationale="", evidence_lines=[])
    raws["b"] = json.dumps(document).encode()
    ledger = reconcile(raws, rows)
    assert ledger["eligible"] == 1
    assert ledger["withheld_from_training"] == 3
    assert next(case for case in ledger["cases"] if case["id"] == "positive")["provisional_label"] is None


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    raws, rows = fixture_documents()
    probe, packet, reviewers, dataset = (tmp_path / name for name in ("probe", "packet", "reviewers", "dataset"))
    for path in (probe, packet / "blind", reviewers, dataset):
        path.mkdir(parents=True)
    for name in ("protocol.json", "features.json", "comparison.json", "classifiers.json"):
        (probe / name).write_text("{}")
    (probe / "features.npz").write_bytes(b"fixture placeholder, not a feature archive")
    for name, path in (("packet", packet / "blind/cases.json"), ("manifest", packet / "original-manifest.json"),
                       ("mapping", packet / "admin.json"), ("a", reviewers / "a.json"), ("b", reviewers / "b.json")):
        path.write_bytes(raws[name])
    pins = {"reserved_test_accessed": False}
    monkeypatch.setattr("training.provisional_review.load_protocol", lambda *args: ({"dataset": str(dataset), "input_pins": pins}, rows))
    monkeypatch.setattr("training.provisional_review.read_development", lambda *args: (rows, pins))
    monkeypatch.setattr("training.provisional_review.validate_receipt", lambda *args: None)
    output = tmp_path / "output"
    result = prepare(probe, packet, reviewers / "a.json", reviewers / "b.json", output)
    return output, result, rows, raws, probe, packet, reviewers


def test_preparation_retains_raw_reviews_and_never_creates_signed_human_consensus(prepared):
    output, result, _, raws, *_ = prepared
    assert result["reviewed_training_cases"] == 4
    assert result["matched_historical"] == 10
    assert result["matched_provisional"] == 8
    assert result["matched_validation"] == 8
    for key, filename in INPUTS.items():
        assert (output / "review-inputs" / filename).read_bytes() == raws[key]
    protocol, _, _, ledger = load(output)
    assert protocol["approval_report"] == APPROVAL
    assert not ledger["signed_human_consensus"]


@pytest.mark.parametrize("mode", ["raw", "ledger", "rehash_ledger", "counts", "approval", "code", "probe"])
def test_changes_to_preserved_evidence_or_protocol_fail_closed(prepared, mode):
    output, _, _, _, probe, *_ = prepared
    protocol_path = output / "protocol.json"
    protocol = json.loads(protocol_path.read_text())
    if mode == "raw":
        (output / "review-inputs/reviewer-a.json").write_text("changed")
    elif mode in {"ledger", "rehash_ledger"}:
        path = output / "review-decisions.json"
        ledger = json.loads(path.read_text())
        ledger["cases"][0]["provisional_label"] = not ledger["cases"][0]["provisional_label"]
        path.write_text(json.dumps(ledger))
        if mode == "rehash_ledger":
            protocol["ledger_sha256"] = sha(path.read_bytes())
    elif mode == "counts":
        protocol["counts"]["matched_validation"] = 0
    elif mode == "approval":
        protocol["approval_report"]["authenticated_signatures"] = True
    elif mode == "code":
        protocol["implementation_sha256"]["training/provisional_review.py"] = "f" * 64
    else:
        (probe / "comparison.json").write_text("changed")
    protocol_path.write_text(json.dumps(protocol))
    with pytest.raises(ValueError):
        load(output)


def test_existing_outputs_and_experimental_opt_in_are_enforced(prepared, monkeypatch):
    output, _, _, _, probe, packet, reviewers = prepared
    with pytest.raises(FileExistsError):
        prepare(probe, packet, reviewers / "a.json", reviewers / "b.json", output)
    for action in ("prepare", "score"):
        monkeypatch.setattr("sys.argv", ["provisional", action, "--output", str(output)])
        with pytest.raises(SystemExit, match="experimental"):
            main()
