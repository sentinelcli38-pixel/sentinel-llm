import json
from pathlib import Path

import pytest

from training.run_mlx import save_fitted
from training.select_checkpoint import validation_checkpoints


def test_fitted_data_is_immutable_and_idempotent(tmp_path: Path) -> None:
    contents = {"train": "train\n", "valid": "valid\n", "test": "test\n"}
    metadata = {"base_model": {"revision": "fixed"}}
    save_fitted(tmp_path, contents, metadata)
    before = (tmp_path / "fit-manifest.json").read_bytes()
    save_fitted(tmp_path, contents, metadata)
    assert (tmp_path / "fit-manifest.json").read_bytes() == before
    with pytest.raises(ValueError, match="would change"):
        save_fitted(tmp_path, {**contents, "test": "different\n"}, metadata)
    assert (tmp_path / "test.jsonl").read_text() == "test\n"
    assert json.loads(before)["fit_sha256"] == metadata["fit_sha256"]


def test_modified_existing_fit_is_rejected(tmp_path: Path) -> None:
    contents = {"train": "data\n"}
    metadata = {"base_model": {"revision": "fixed"}}
    save_fitted(tmp_path, contents, metadata)
    (tmp_path / "train.jsonl").write_text("tampered\n")
    with pytest.raises(ValueError, match="modified"):
        save_fitted(tmp_path, contents, metadata)


def test_checkpoint_parser_reads_validation_not_training_loss() -> None:
    log = "    20    \x1b[1mval\x1b[0m 0.046 34s\n    20    0.047 9 0.4k\n    40    val 0.039 34s\n"
    assert validation_checkpoints(log) == [(20, 0.046), (40, 0.039)]
