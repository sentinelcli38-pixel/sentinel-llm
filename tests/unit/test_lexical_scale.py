import json

import pytest

from training.lexical_scale import (
    IMPLEMENTATIONS,
    ROOT,
    SCALE_PLAN,
    file_hash,
    load,
    main,
    prepare,
)


@pytest.mark.parametrize("mode", ["valid", "code", "original", "dataset", "selection", "duplicate_subset", "missing_subset"])
def test_scale_protocol_revalidates_all_identities_and_pins(tmp_path, monkeypatch, mode):
    source = tmp_path / "original.json"
    source.write_text("original fixture")
    rows = {"train": [{"id": "train"}], "valid": [{"id": "first"}, {"id": "second"}]}
    pins = {"reserved_test_accessed": False}
    document = {"plan": SCALE_PLAN, "implementation_sha256": {name: file_hash(ROOT / name) for name in IMPLEMENTATIONS},
                "original_probe_pins": {str(source): file_hash(source)}, "dataset": str(tmp_path / "dataset"),
                "input_pins": pins, "split_ids": {split: [r["id"] for r in items] for split, items in rows.items()},
                "original_valid_ids": ["first"]}
    monkeypatch.setattr("training.lexical_scale.read_development", lambda *args: (rows, pins))
    if mode == "code":
        document["implementation_sha256"][IMPLEMENTATIONS[0]] = "f" * 64
    elif mode == "original":
        source.write_text("changed")
    elif mode == "dataset":
        document["input_pins"] = {}
    elif mode == "selection":
        document["split_ids"]["valid"].pop()
    elif mode == "duplicate_subset":
        document["original_valid_ids"] *= 2
    elif mode == "missing_subset":
        document["original_valid_ids"] = ["missing"]
    (tmp_path / "protocol.json").write_text(json.dumps(document))
    if mode == "valid":
        _, actual = load(tmp_path)
        assert actual == rows
    else:
        with pytest.raises(ValueError):
            load(tmp_path)


def test_scale_preserves_existing_outputs_and_frozen_inputs(tmp_path):
    (tmp_path / "keep").write_text("untouched")
    with pytest.raises(FileExistsError):
        prepare(tmp_path / "dataset", tmp_path / "probe", tmp_path)
    assert (tmp_path / "keep").read_text() == "untouched"
    with pytest.raises(ValueError, match="outside"):
        prepare(tmp_path, tmp_path, tmp_path / "new")


def test_scoring_requires_experimental_opt_in(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.argv", ["lexical", "score", "--output", str(tmp_path)])
    with pytest.raises(SystemExit, match="experimental"):
        main()
