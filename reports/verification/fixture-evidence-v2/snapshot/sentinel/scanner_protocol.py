"""Local code/runtime pins for a preregistered scanner replication."""

import hashlib
import platform
import shutil
from importlib.metadata import version
from pathlib import Path

CODE_ROOT = Path(__file__).resolve().parents[1]


def scanner_protocol(static_binary: Path | None, timeout_seconds: int) -> dict:
    if timeout_seconds < 1:
        raise ValueError("Scanner protocol requires a positive command timeout")
    sources = sorted((CODE_ROOT / "sentinel").rglob("*.py")) + [CODE_ROOT / "pyproject.toml"]
    binaries = {"slither": shutil.which("slither"),
                "sentinel-static": str(static_binary) if static_binary else shutil.which("sentinel-static")}
    executable_pins = {}
    for name, location in binaries.items():
        if not location or not Path(location).is_file():
            raise ValueError(f"Frozen comparison requires installed {name}")
        path = Path(location).resolve()
        executable_pins[name] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    return {
        "schema_version": 1,
        "implementation_sha256": {str(path.relative_to(CODE_ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                                  for path in sources},
        "executables": executable_pins,
        "local_environment": {"python": platform.python_version(),
                              "packages": {name: version(name) for name in ("slither-analyzer", "crytic-compile", "pydantic")}},
        "profiles": ["slither", "sentinel-static"], "command_timeout_seconds": timeout_seconds,
        "minimum_per_label_per_property": 20, "minimum_recall": 0.8, "minimum_specificity": 0.8,
        "scope": "Disjoint CGT scanner replication; not a final model test or security certification. "
                 "Executable pins hash entry points, not their complete external environments.",
    }


def verify_scanner_protocol(expected: dict, static_binary: Path | None, timeout_seconds: int) -> None:
    if expected != scanner_protocol(static_binary, timeout_seconds):
        raise ValueError("Scanner implementation or runtime differs from the frozen comparison protocol")
