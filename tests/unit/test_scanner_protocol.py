import json

import pytest

from sentinel.scanner_protocol import scanner_protocol, verify_scanner_protocol


@pytest.fixture
def environment(tmp_path, monkeypatch):
    from sentinel import scanner_protocol as module

    (tmp_path / "sentinel").mkdir()
    code = tmp_path / "sentinel/detector.py"
    code.write_text("original")
    (tmp_path / "pyproject.toml").write_text("project")
    slither, extension = (tmp_path / name for name in ("slither", "sentinel-static"))
    slither.write_bytes(b"baseline")
    extension.write_bytes(b"extension")
    monkeypatch.setattr(module, "CODE_ROOT", tmp_path)
    monkeypatch.setattr(module.shutil, "which", lambda name: str(tmp_path / name))
    monkeypatch.setattr(module, "version", lambda name: "1.0")
    return tmp_path, code, slither, extension


def test_protocol_survives_json_round_trip(environment):
    _, _, _, extension = environment
    snapshot = json.loads(json.dumps(scanner_protocol(extension, 30)))
    assert set(snapshot["implementation_sha256"]) == {"sentinel/detector.py", "pyproject.toml"}
    verify_scanner_protocol(snapshot, extension, 30)


@pytest.mark.parametrize("change", ["source", "new_source", "binary", "binary_path", "timeout", "dependency"])
def test_protocol_fails_closed_on_drift(environment, monkeypatch, change):
    root, code, slither, extension = environment
    snapshot = scanner_protocol(extension, 30)
    timeout = 30
    if change == "source":
        code.write_text("changed")
    elif change == "new_source":
        (root / "sentinel/new.py").write_text("new implementation")
    elif change == "binary":
        slither.write_bytes(b"changed executable")
    elif change == "binary_path":
        replacement = root / "replacement"
        replacement.write_bytes(extension.read_bytes())
        extension = replacement
    elif change == "timeout":
        timeout = 120
    else:
        monkeypatch.setattr("sentinel.scanner_protocol.version", lambda name: "2.0")
    with pytest.raises(ValueError, match="frozen comparison"):
        verify_scanner_protocol(snapshot, extension, timeout)


def test_missing_analyzer_cannot_be_frozen(environment):
    _, _, slither, extension = environment
    slither.unlink()
    with pytest.raises(ValueError, match="installed slither"):
        scanner_protocol(extension, 30)
