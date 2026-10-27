"""Download a pinned base model, fit token budgets, and run local MLX training."""

import argparse
import hashlib
import importlib.metadata
import json
import platform
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml

# The optional MLX environment is independent of Sentinel's web/API dependencies.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sentinel.modeling.data import audit_dataset, read_jsonl
from sentinel.modeling.properties import balanced_training, evaluation_subset

BASE_REPO = "mlx-community/Qwen2.5-Coder-1.5B-Instruct-4bit"


def save_fitted(fitted: Path, contents: dict[str, str], metadata: dict) -> None:
    hashes = {split: hashlib.sha256(content.encode()).hexdigest() for split, content in contents.items()}
    manifest_path = fitted / "fit-manifest.json"
    if manifest_path.exists():
        previous = json.loads(manifest_path.read_text())
        if previous["fit_sha256"] != hashes or previous["base_model"] != metadata["base_model"]:
            raise ValueError("Fitted dataset would change; use a new data path in the experiment config")
        for split, digest in hashes.items():
            path = fitted / f"{split}.jsonl"
            if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError("Existing fitted data was modified; preserve it and use a new path")
        return
    if any((fitted / f"{split}.jsonl").exists() for split in contents):
        raise ValueError("Unmanifested fitted data already exists; use a new data path")
    fitted.mkdir(parents=True, exist_ok=True)
    for split, content in contents.items():
        (fitted / f"{split}.jsonl").write_text(content, encoding="utf-8")
    metadata["fit_sha256"] = hashes
    manifest_path.write_text(json.dumps(metadata, indent=2) + "\n")


def setup(config_path: Path, dataset: Path, revision: str | None = None) -> dict:
    from huggingface_hub import HfApi, snapshot_download
    from transformers import AutoTokenizer

    config = yaml.safe_load(config_path.read_text())
    audit = audit_dataset(dataset)
    destination = Path(config["model"])
    if (destination / "sentinel-base.json").is_file():
        base = json.loads((destination / "sentinel-base.json").read_text())
        if revision and base["revision"] != revision:
            raise ValueError("Existing base model has a different revision")
    else:
        sha = HfApi().model_info(BASE_REPO, revision=revision).sha
        snapshot_download(
            BASE_REPO, revision=sha, local_dir=str(destination),
            allow_patterns=["*.json", "*.safetensors", "*.txt", "*.jinja", "README.md", "LICENSE"],
        )
        base = {"repository": BASE_REPO, "revision": sha}
        (destination / "sentinel-base.json").write_text(json.dumps(base, indent=2) + "\n")
    tokenizer = AutoTokenizer.from_pretrained(str(destination), trust_remote_code=False)
    fitted = Path(config["data"])
    if fitted.resolve() == dataset.resolve():
        raise ValueError("Fitted output must differ from the prepared dataset")
    counts = {}
    excluded = {}
    balance = None
    fitted_available = {}
    selection_excluded = {}
    contents = {}
    for split in ("train", "valid", "test"):
        rows = read_jsonl(dataset / f"{split}.jsonl")
        selected = [row for row in rows if len(tokenizer.encode(
            tokenizer.apply_chat_template(row["messages"], tokenize=False), add_special_tokens=False,
        )) <= config["max_seq_length"]]
        if not selected:
            raise ValueError(f"No {split} examples fit the token budget; increase max_seq_length")
        fitted_available[split] = len(selected)
        excluded[split] = len(rows) - len(selected)
        if config.get("balance_per_bucket"):
            if split == "train":
                selected, balance = balanced_training(selected, config["balance_per_bucket"], config["seed"])
            elif config.get("evaluation_per_bucket"):
                selected = evaluation_subset(selected, config["evaluation_per_bucket"], config["seed"])
        selection_excluded[split] = max(0, fitted_available[split] - len({row["id"] for row in selected}))
        contents[split] = "".join(json.dumps(row) + "\n" for row in selected)
        counts[split] = len(selected)
    metadata = {
        "base_model": base, "dataset_audit": audit, "config": config,
        "token_budget_counts": counts, "overlength_excluded": excluded,
        "token_budget_available": fitted_available, "selection_excluded": selection_excluded,
        "training_balance": balance,
        "fit_sha256": {split: hashlib.sha256(content.encode()).hexdigest() for split, content in contents.items()},
    }
    save_fitted(fitted, contents, metadata)
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("training/mac-8gb.yaml"))
    parser.add_argument("--dataset", type=Path, default=Path("datasets/model-training"))
    parser.add_argument("--revision")
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--iters", type=int)
    args = parser.parse_args()
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise SystemExit("This configuration requires an Apple Silicon Mac")
    if args.iters is not None and args.iters < 1:
        raise SystemExit("--iters must be positive")
    requested_config = yaml.safe_load(args.config.read_text())
    if not args.prepare_only and (Path(requested_config["adapter_path"]) / "adapters.safetensors").exists():
        raise SystemExit("Adapter already exists. Choose a new adapter_path in a copied config.")
    if not args.prepare_only and (Path(requested_config["adapter_path"]).parent / "run.json").exists():
        raise SystemExit("Run metadata already exists. Choose a new adapter_path to preserve the prior run.")
    metadata = setup(args.config, args.dataset, args.revision)
    print(json.dumps(metadata, indent=2), flush=True)
    if args.prepare_only:
        return
    config = metadata["config"]
    output = Path(config["adapter_path"]).parent
    output.mkdir(parents=True, exist_ok=True)
    if (Path(config["adapter_path"]) / "adapters.safetensors").exists():
        raise SystemExit("Adapter already exists. Choose a new adapter_path in a copied config.")
    command = [sys.executable, "-m", "mlx_lm", "lora", "--config", str(args.config)]
    if args.iters is not None:
        command.extend(["--iters", str(args.iters)])
        config["iters"] = args.iters
    record = {
        **metadata, "status": "started", "command": command,
        "started_at": datetime.now(UTC).isoformat(), "platform": platform.platform(),
        "packages": {name: importlib.metadata.version(name) for name in ("mlx", "mlx-lm", "transformers")},
    }
    record_path = output / "run.json"
    record_path.write_text(json.dumps(record, indent=2) + "\n")
    with (output / "training.log").open("w") as log:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            for line in process.stdout:
                print(line, end="", flush=True)
                log.write(line)
                log.flush()
            code = process.wait()
        except KeyboardInterrupt:
            process.terminate()
            process.wait()
            record["status"] = "interrupted"
            record_path.write_text(json.dumps(record, indent=2) + "\n")
            raise
    record["status"] = "completed" if code == 0 else "failed"
    record["exit_code"] = code
    record["finished_at"] = datetime.now(UTC).isoformat()
    record_path.write_text(json.dumps(record, indent=2) + "\n")
    raise SystemExit(code)


if __name__ == "__main__":
    main()
