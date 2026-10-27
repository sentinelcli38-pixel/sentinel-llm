import hashlib
import json

import pytest

from scripts import prepare_locked_external as module


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    upstream, stage = tmp_path / "upstream", tmp_path / "stage"
    upstream.mkdir()
    (stage / "npm/@test/contracts").mkdir(parents=True)
    source = b"pragma solidity ^0.8.20; contract Token {}"
    (stage / "npm/@test/contracts/Token.sol").write_bytes(source)
    package = {"name": "@test/contracts", "version": "1.2.3", "resolved": "https://registry.npmjs.org/test.tgz",
               "integrity": "sha512-fixture", "files_sha256": {"npm/@test/contracts/Token.sol": digest(source)}}
    lock = {"packages": {"node_modules/@test/contracts": {key: package[key] for key in ("version", "resolved", "integrity")}}}
    (upstream / "lock.json").write_text(json.dumps(lock))
    (upstream / "config.ts").write_text("throw Error('not executable');")
    spec = {"repository": "https://example.test/repo", "revision": "PIN", "packages": ["@test/contracts"],
            "lockfile": "lock.json", "build_config": "config.ts", "build_settings": {
                "solc_version": "0.8.20", "optimizer": True, "optimizer_runs": 200, "evm_version": "paris"}}
    for key in ("lockfile", "build_config"):
        spec[f"{key}_sha256"] = digest((upstream / spec[key]).read_bytes())
    receipt = {key: spec[key] for key in ("repository", "revision", "build_settings", "lockfile_sha256", "build_config_sha256")}
    receipt["packages"] = [package]
    path = stage / "receipt.json"
    path.write_text(json.dumps(receipt))
    monkeypatch.setattr(module, "git_bytes", lambda root, revision, name: (root / name).read_bytes())
    return stage, digest(path.read_bytes()), spec, upstream


def test_dependency_inputs_keep_audited_compiler_settings_and_source_bytes(inputs):
    stage, pin, spec, upstream = inputs
    sources, receipt = module.verified_dependencies(stage, pin, spec, upstream)
    assert sources["lib/npm/@test/contracts/Token.sol"] == (stage / "npm/@test/contracts/Token.sol").read_bytes()
    assert receipt["build_settings"] == spec["build_settings"]


@pytest.mark.parametrize("change", ["source", "extra_file", "receipt", "lock", "configuration", "package", "settings"])
def test_changed_dependency_or_authoritative_inputs_are_rejected(inputs, change):
    stage, pin, spec, upstream = inputs
    if change == "source":
        (stage / "npm/@test/contracts/Token.sol").write_text("changed")
    elif change == "extra_file":
        (stage / "unexpected.js").write_text("unexpected")
    elif change == "receipt":
        (stage / "receipt.json").write_text("changed")
    elif change == "lock":
        (upstream / "lock.json").write_text("changed")
    elif change == "configuration":
        (upstream / "config.ts").write_text("changed")
    elif change == "package":
        spec["packages"] = ["@test/other"]
    else:
        spec["build_settings"]["optimizer_runs"] = 999
    with pytest.raises(ValueError):
        module.verified_dependencies(stage, pin, spec, upstream)


def test_no_existing_benchmark_directory_can_be_replaced(tmp_path):
    output = tmp_path / "existing"
    output.mkdir()
    with pytest.raises(ValueError, match="already exists"):
        module.prepare(tmp_path / "unused", tmp_path, tmp_path, tmp_path, output, tmp_path, tmp_path,
                       smartbugs=tmp_path, fitted=tmp_path, cgt=tmp_path, exclusions=[])
