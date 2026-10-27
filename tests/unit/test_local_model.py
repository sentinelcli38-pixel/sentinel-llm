import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from training.local_model import (
    REPOSITORY,
    adapter_evidence,
    file_hash,
    main,
    restore,
    specification,
    status,
)

REVISION = "b" * 40
WEIGHTS = b"Synthetic unit-test bytes, not model weights."


def model_fixture(tmp_path):
    model = tmp_path / "model"
    model.mkdir()
    (model / "sentinel-base.json").write_text(json.dumps({"repository": REPOSITORY, "revision": REVISION}))
    contents = {"config.json": {"model_type": "qwen2", "num_hidden_layers": 28,
                                "hidden_size": 1536, "quantization": {"bits": 4}},
                "model.safetensors.index.json": {"weight_map": {"tensor": "model.safetensors"}},
                "tokenizer.json": {"unit_test": True}, "tokenizer_config.json": {"unit_test": True}}
    for name, value in contents.items():
        (model / name).write_text(json.dumps(value))
    siblings = [SimpleNamespace(rfilename=name, size=(model / name).stat().st_size, lfs=None,
                               blob_id=file_hash(model / name, "git_blob_sha1")) for name in contents]
    import hashlib
    siblings.append(SimpleNamespace(rfilename="model.safetensors", size=len(WEIGHTS),
                                    lfs=SimpleNamespace(sha256=hashlib.sha256(WEIGHTS).hexdigest())))
    info = SimpleNamespace(sha=REVISION, siblings=siblings)
    calls = []

    def model_info(repository, **kwargs):
        assert repository == REPOSITORY and kwargs == {"revision": REVISION, "files_metadata": True}
        return info

    def download(repository, name, **kwargs):
        assert repository == REPOSITORY and name == "model.safetensors"
        assert kwargs == {"revision": REVISION, "local_dir": str(model), "token": False}
        calls.append(name)
        (model / name).write_bytes(WEIGHTS)
        return str(model / name)
    return model, SimpleNamespace(model_info=model_info), download, info, calls


def test_missing_weights_are_detected_without_importing_mlx_or_reading_datasets(tmp_path, monkeypatch):
    model, _, _, _, _ = model_fixture(tmp_path)
    original = Path.read_text

    def no_dataset_reads(path, *args, **kwargs):
        assert path.name not in {"train.jsonl", "valid.jsonl", "test.jsonl"}
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "read_text", no_dataset_reads)
    result = status(model)
    assert result["missing_files"] == ["model.safetensors"]
    assert not result["ready_for_local_inference"]
    assert result["reserved_test_accessed"] is False


def test_restore_verifies_pins_and_is_idempotent_without_overwriting_receipt(tmp_path):
    model, api, download, _, calls = model_fixture(tmp_path)
    before = (model / "config.json").read_bytes()
    assert restore(model, api=api, download=download)["ready_for_local_inference"]
    receipt = (model / "sentinel-weights.json").read_bytes()
    assert restore(model, api=api, download=download)["ready_for_local_inference"]
    assert calls == ["model.safetensors"]
    assert (model / "sentinel-weights.json").read_bytes() == receipt
    assert (model / "config.json").read_bytes() == before
    assert not status(model)["qualified_as_security_detector"]


@pytest.mark.parametrize("mode", ["repository", "revision", "architecture", "quantization", "empty_index", "escape_index"])
def test_model_identity_and_index_are_fail_closed(tmp_path, mode):
    model, _, _, _, _ = model_fixture(tmp_path)
    name = "sentinel-base.json" if mode in {"repository", "revision"} else "config.json" if mode in {"architecture", "quantization"} else "model.safetensors.index.json"
    document = json.loads((model / name).read_text())
    if mode == "repository":
        document["repository"] = "different/model"
    elif mode == "revision":
        document["revision"] = "main"
    elif mode == "architecture":
        document["num_hidden_layers"] = 3
    elif mode == "quantization":
        document["quantization"]["bits"] = 8
    elif mode == "empty_index":
        document["weight_map"] = {}
    else:
        document["weight_map"] = {"tensor": "../other.safetensors"}
    (model / name).write_text(json.dumps(document))
    with pytest.raises(ValueError):
        specification(model)


@pytest.mark.parametrize("mode", ["upstream_revision", "missing_upstream", "missing_digest", "corrupt_existing",
                                  "changed_config", "corrupt_download", "disk_space"])
def test_restoration_does_not_accept_corruption_or_overwrite_existing_files(tmp_path, monkeypatch, mode):
    model, api, download, info, calls = model_fixture(tmp_path)
    if mode == "upstream_revision":
        info.sha = "0" * 40
    elif mode == "missing_upstream":
        info.siblings.pop()
    elif mode == "missing_digest":
        info.siblings[-1].lfs.sha256 = "not-a-hash"
    elif mode == "corrupt_existing":
        (model / "model.safetensors").write_bytes(b"preserve existing corrupt file for investigation")
    elif mode == "changed_config":
        (model / "config.json").write_text((model / "config.json").read_text() + " ")
    elif mode == "corrupt_download":
        def download(*args, **kwargs):
            (model / "model.safetensors").write_bytes(b"broken download")
    elif mode == "disk_space":
        monkeypatch.setattr("training.local_model.shutil.disk_usage", lambda path: SimpleNamespace(free=0))
    original = (model / "model.safetensors").read_bytes() if (model / "model.safetensors").exists() else None
    with pytest.raises(ValueError):
        restore(model, api=api, download=download)
    assert not (model / "sentinel-weights.json").exists()
    assert calls == []
    if original:
        assert (model / "model.safetensors").read_bytes() == original


def test_readiness_rechecks_weight_hashes_and_does_not_equate_presence_with_integrity(tmp_path):
    model, api, download, _, _ = model_fixture(tmp_path)
    restore(model, api=api, download=download)
    (model / "model.safetensors").write_bytes(b"x" * len(WEIGHTS))
    result = status(model)
    assert not result["missing_files"]
    assert result["integrity_errors"]
    assert not result["ready_for_local_inference"]


def test_receipt_cannot_reference_arbitrary_files(tmp_path):
    model, api, download, _, _ = model_fixture(tmp_path)
    restore(model, api=api, download=download)
    path = model / "sentinel-weights.json"
    receipt = json.loads(path.read_text())
    receipt["files"]["../unrelated"] = {}
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="Unexpected path"):
        status(model)


def test_adapter_must_match_completed_run_base_and_selected_checkpoint(tmp_path):
    run = tmp_path / "run"
    adapter = run / "selected-adapter"
    adapter.mkdir(parents=True)
    (adapter / "adapters.safetensors").write_bytes(b"unit-test-only")
    (adapter / "adapter_config.json").write_text("{}")
    base = {"repository": REPOSITORY, "revision": REVISION}
    record = {"status": "completed", "base_model": base, "config": {"balance_per_bucket": 16},
              "fit_sha256": {"valid": "a" * 64}}
    (run / "run.json").write_text(json.dumps(record))
    selection = {"checkpoint_sha256": file_hash(adapter / "adapters.safetensors"), "validation_sha256": "a" * 64}
    (adapter / "selection.json").write_text(json.dumps(selection))
    assert adapter_evidence(adapter, base)["sha256"] == selection["checkpoint_sha256"]
    (adapter / "adapters.safetensors").write_bytes(b"changed")
    with pytest.raises(ValueError):
        adapter_evidence(adapter, base)


def test_cli_requires_experimental_opt_in_and_never_overwrites_reports(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.argv", ["local-model", "smoke"])
    with pytest.raises(SystemExit, match="experimental"):
        main()
    output = tmp_path / "existing.json"
    output.write_text("preserve")
    monkeypatch.setattr("sys.argv", ["local-model", "status", "--output", str(output)])
    with pytest.raises(FileExistsError):
        main()
    assert output.read_text() == "preserve"
