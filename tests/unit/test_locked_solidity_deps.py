import base64
import hashlib
import io
import json
import tarfile
from types import SimpleNamespace

import pytest

from scripts import locked_solidity_deps as module


def archive(extra=()):
    stream = io.BytesIO()
    files = {"package/package.json": json.dumps({"name": "@test/contracts", "version": "1.2.3", "license": "MIT"}).encode(),
             "package/Token.sol": b"pragma solidity ^0.8.20; contract Token {}",
             "package/LICENSE": b"MIT fixture", "package/install.js": b"throw Error('must not run');"}
    with tarfile.open(fileobj=stream, mode="w:gz") as handle:
        for name, raw in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(raw)
            handle.addfile(member, io.BytesIO(raw))
        for member, raw in extra:
            handle.addfile(member, io.BytesIO(raw) if raw is not None else None)
    raw = stream.getvalue()
    return raw, "sha512-" + base64.b64encode(hashlib.sha512(raw).digest()).decode()


def test_archive_retains_sources_and_licenses_but_not_executable_scripts():
    raw, integrity = archive()
    files = module.solidity_files(raw, integrity)
    assert set(files) == {"Token.sol", "LICENSE", "package.json"}
    assert files["LICENSE"] == b"MIT fixture"


@pytest.mark.parametrize("name", ["package/../escape.sol", "/package/Token.sol", "other/Token.sol", "package/a\\b.sol",
                                 "package/Token.sol", "package/a//b.sol", "package/./Token.sol"])
def test_unsafe_and_duplicate_paths_are_rejected(name):
    member = tarfile.TarInfo(name)
    member.size = 1
    raw, integrity = archive([(member, b"x")])
    with pytest.raises(ValueError):
        module.solidity_files(raw, integrity)


@pytest.mark.parametrize("kind", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE])
def test_archive_links_and_devices_are_rejected_even_when_not_solidity(kind):
    member = tarfile.TarInfo("package/unsafe.txt")
    member.type = kind
    member.linkname = "../../outside"
    raw, integrity = archive([(member, None)])
    with pytest.raises(ValueError, match="Links"):
        module.solidity_files(raw, integrity)


def test_integrity_and_resource_limits_are_enforced(monkeypatch):
    raw, integrity = archive()
    with pytest.raises(ValueError, match="integrity"):
        module.solidity_files(raw + b"changed", integrity)
    with pytest.raises(ValueError, match="SHA-512"):
        module.solidity_files(raw, "sha1-old")
    monkeypatch.setattr(module, "MAX_ARCHIVE", 10)
    with pytest.raises(ValueError):
        module.solidity_files(raw, integrity)
    monkeypatch.setattr(module, "MAX_ARCHIVE", 20_000_000)
    monkeypatch.setattr(module, "MAX_UNPACKED", 1)
    with pytest.raises(ValueError, match="unpacked"):
        module.solidity_files(raw, integrity)


@pytest.mark.parametrize("url", ["http://registry.npmjs.org/a.tgz", "https://localhost/a.tgz", "https://registry.npmjs.org.evil.test/a.tgz",
                                "https://u:p@registry.npmjs.org/a.tgz", "https://registry.npmjs.org:444/a.tgz",
                                "https://registry.npmjs.org/a.tgz?token=x", "https://registry.npmjs.org/a.zip"])
def test_unapproved_network_targets_are_rejected(url):
    with pytest.raises(ValueError):
        module.registry_url(url)


def test_redirect_is_validated_before_following_it():
    with pytest.raises(ValueError):
        module.RegistryRedirects().redirect_request(None, None, 302, "redirect", {}, "http://127.0.0.1/a.tgz")


@pytest.fixture
def staged_inputs(tmp_path, monkeypatch):
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    raw, integrity = archive()
    lock = {"lockfileVersion": 3, "packages": {"node_modules/@test/contracts": {
        "version": "1.2.3", "integrity": integrity, "resolved": "https://registry.npmjs.org/@test/contracts/-/contracts-1.2.3.tgz"}}}
    (upstream / "package-lock.json").write_text(json.dumps(lock))
    (upstream / "hardhat.config.ts").write_text("throw Error('configuration must not execute');")
    spec = {"repository": "https://example.test/repo", "revision": "PIN", "lockfile": "package-lock.json",
            "build_config": "hardhat.config.ts", "build_settings": {"solc_version": "0.8.20"}, "packages": ["@test/contracts"]}
    for key in ("lockfile", "build_config"):
        spec[f"{key}_sha256"] = hashlib.sha256((upstream / spec[key]).read_bytes()).hexdigest()
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(spec))
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(stdout="PIN"))
    monkeypatch.setattr(module, "git_bytes", lambda root, revision, name: (root / name).read_bytes())
    return path, upstream, tmp_path / "stage", raw


def test_staging_pins_exact_locked_package_and_refuses_overwrite(staged_inputs):
    spec, upstream, output, raw = staged_inputs
    receipt_path = module.stage(spec, upstream, output, fetch=lambda url: raw)
    receipt = json.loads(receipt_path.read_text())
    assert receipt["packages"][0]["version"] == "1.2.3"
    assert receipt["packages"][0]["archive_sha256"] == hashlib.sha256(raw).hexdigest()
    assert (output / "npm/@test/contracts/Token.sol").is_file()
    assert not (output / "npm/@test/contracts/install.js").exists()
    with pytest.raises(ValueError, match="already exists"):
        module.stage(spec, upstream, output, fetch=lambda url: raw)


def test_changed_lockfile_is_rejected_before_network(staged_inputs):
    spec, upstream, output, _ = staged_inputs
    (upstream / "package-lock.json").write_text("changed")

    def forbidden(url):
        pytest.fail("Unpinned inputs cannot trigger downloads")

    with pytest.raises(ValueError, match="pin differs"):
        module.stage(spec, upstream, output, fetch=forbidden)
    assert not output.exists()


def test_wrong_archive_identity_leaves_no_partial_stage(staged_inputs):
    spec, upstream, output, raw = staged_inputs
    lock_path = upstream / "package-lock.json"
    lock = json.loads(lock_path.read_text())
    lock["packages"]["node_modules/@test/contracts"]["version"] = "9.9.9"
    lock_path.write_text(json.dumps(lock))
    document = json.loads(spec.read_text())
    document["lockfile_sha256"] = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    spec.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="identity/version"):
        module.stage(spec, upstream, output, fetch=lambda url: raw)
    assert not output.exists()
