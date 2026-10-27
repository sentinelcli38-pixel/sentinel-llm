"""Select a saved checkpoint by reported validation loss, preserving all weights."""

import argparse
import hashlib
import json
import re
import shutil
from pathlib import Path


def validation_checkpoints(log: str) -> list[tuple[int, float]]:
    clean = re.sub(r"\x1b\[[0-9;]*m", "", log)
    return [(int(step), float(loss)) for step, loss in re.findall(r"^\s*(\d+)\s+val\s+(\d+(?:\.\d+)?)\s", clean, re.MULTILINE)]


def select(run: Path) -> dict:
    record = json.loads((run / "run.json").read_text())
    if record["status"] != "completed":
        raise ValueError("Only a completed run can select a checkpoint")
    checkpoints = validation_checkpoints((run / "training.log").read_text())
    adapter = Path(record["config"]["adapter_path"])
    candidates = [(step, loss) for step, loss in checkpoints if (adapter / f"{step:07d}_adapters.safetensors").is_file()]
    if not candidates:
        raise ValueError("No saved checkpoint has a reported validation loss")
    step, loss = min(candidates, key=lambda item: (item[1], item[0]))
    source = adapter / f"{step:07d}_adapters.safetensors"
    output = run / "selected-adapter"
    if output.exists():
        raise ValueError("Selected adapter already exists; preserve its recorded selection")
    selection = {"step": step, "reported_validation_loss": loss,
                 "rule": "Minimum reported validation loss; choose earliest step on rounded-loss ties. Never reads test data.",
                 "checkpoint_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                 "validation_sha256": record["fit_sha256"]["valid"],
                 "candidates": [{"step": index, "reported_validation_loss": value} for index, value in candidates]}
    output.mkdir()
    shutil.copyfile(source, output / "adapters.safetensors")
    shutil.copyfile(adapter / "adapter_config.json", output / "adapter_config.json")
    (output / "selection.json").write_text(json.dumps(selection, indent=2) + "\n")
    return selection


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, default=Path("training/runs/mac-properties"))
    args = parser.parse_args()
    print(json.dumps(select(args.run), indent=2))


if __name__ == "__main__":
    main()
