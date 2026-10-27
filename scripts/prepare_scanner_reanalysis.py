"""Declare development reuse without overwriting a prior frozen scanner protocol."""

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.experiments import ExperimentManifest
from sentinel.scanner_protocol import scanner_protocol


def prepare(original: Path, output: Path, protocol: dict) -> Path:
    if output.exists():
        raise ValueError("Output already exists; preserve prior evaluation evidence")
    raw = original.read_bytes()
    document = ExperimentManifest.model_validate_json(raw).model_dump(mode="json")
    previous_protocol = document["provenance"].pop("scanner_protocol", None)
    if not previous_protocol:
        raise ValueError("Reanalysis requires a previously frozen comparison")
    for case in document["cases"]:
        case["project_path"] = str((original.parent / case["project_path"]).resolve())
        case["group"] = "development"
    document["name"] += "-development-reanalysis"
    document["provenance"].update(
        original_manifest_sha256=hashlib.sha256(raw).hexdigest(), original_manifest_path=str(original.resolve()),
        previous_scanner_protocol=previous_protocol, scanner_protocol=protocol,
        analysis_scope="Development reuse of previously observed cases. Not independent validation for this detector version.")
    output.mkdir(parents=True)
    path = output / "manifest.json"
    path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--static-binary", type=Path, default=Path(".venv/bin/sentinel-static"))
    args = parser.parse_args()
    print(f"Development reanalysis manifest: {prepare(args.original, args.output, scanner_protocol(args.static_binary, 30))}")


if __name__ == "__main__":
    main()
