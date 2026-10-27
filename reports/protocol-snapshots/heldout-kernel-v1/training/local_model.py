"""Restore and verify the existing pinned 1.5B model without touching datasets."""

import argparse
import hashlib
import json
import platform
import re
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "mlx-community/Qwen2.5-Coder-1.5B-Instruct-4bit"
ASSETS = ("config.json", "model.safetensors.index.json", "tokenizer.json", "tokenizer_config.json",
          "added_tokens.json", "special_tokens_map.json", "merges.txt", "vocab.json", "README.md")
REQUIRED_ASSETS = set(ASSETS[:4])
RECEIPT = "sentinel-weights.json"
SMOKE_SOURCE = "contract Example { function value() external pure returns (uint256) { return 1; } }"


def file_hash(path: Path, algorithm: str = "sha256") -> str:
    if algorithm not in {"sha256", "git_blob_sha1"}:
        raise ValueError("Unsupported integrity algorithm")
    digest = hashlib.new("sha1" if algorithm == "git_blob_sha1" else algorithm)
    if algorithm == "git_blob_sha1":
        digest.update(f"blob {path.stat().st_size}\0".encode())
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def specification(model: Path) -> tuple[dict, list[str]]:
    base = json.loads((model / "sentinel-base.json").read_text())
    if base.get("repository") != REPOSITORY or not re.fullmatch(r"[a-f0-9]{40}", base.get("revision", "")):
        raise ValueError("Only the existing repository and a full pinned revision are supported")
    config = json.loads((model / "config.json").read_text())
    if (config.get("model_type") != "qwen2" or config.get("num_hidden_layers") != 28
            or config.get("hidden_size") != 1536 or config.get("quantization", {}).get("bits") != 4):
        raise ValueError("Configuration does not describe the expected 4-bit Qwen 1.5B architecture")
    index = json.loads((model / "model.safetensors.index.json").read_text())
    mapping = index.get("weight_map")
    if not isinstance(mapping, dict) or not mapping:
        raise ValueError("A nonempty weight index is required")
    values = list(mapping.values())
    if any(not isinstance(name, str) or not re.fullmatch(r"model(?:-[0-9]+-of-[0-9]+)?\.safetensors", name) for name in values):
        raise ValueError("Weight index must name local model safetensor shards only")
    return base, sorted(set(values))


def status(model: Path) -> dict:
    base, shards = specification(model)
    missing = sorted(name for name in REQUIRED_ASSETS | set(shards) if not (model / name).is_file())
    receipt_path = model / RECEIPT
    errors = []
    if receipt_path.is_file():
        receipt = json.loads(receipt_path.read_text())
        if receipt.get("base_model") != base:
            errors.append("Weight receipt is for a different model/revision")
        files = receipt.get("files", {})
        if not isinstance(files, dict):
            raise ValueError("Weight receipt files must be an object")
        if not (REQUIRED_ASSETS | set(shards)) <= files.keys():
            errors.append("Weight receipt does not cover every required model file")
        for name, pin in files.items():
            if name not in set(ASSETS) | set(shards):
                raise ValueError("Unexpected path in weight receipt")
            if (not isinstance(pin, dict) or pin.get("algorithm") not in {"sha256", "git_blob_sha1"}
                    or type(pin.get("bytes")) is not int or pin["bytes"] < 1
                    or not isinstance(pin.get("digest"), str)):
                raise ValueError("Malformed model file integrity pin")
            path = model / name
            if (not path.is_file() or path.is_symlink() or path.stat().st_size != pin["bytes"]
                    or file_hash(path, pin["algorithm"]) != pin["digest"]):
                errors.append(f"Missing or changed pinned model file: {name}")
    else:
        errors.append("No verified weight receipt; run restore to check pinned upstream hashes")
    return {"model": str(model.resolve()), "base_model": base, "quantization_bits": 4,
            "weight_shards": shards, "missing_files": missing, "integrity_errors": errors,
            "ready_for_local_inference": not missing and not errors,
            "qualified_as_security_detector": False, "reserved_test_accessed": False}


def restore(model: Path, *, api=None, download=None) -> dict:
    base, shards = specification(model)
    if api is None or download is None:
        from huggingface_hub import HfApi, hf_hub_download
        api, download = HfApi(token=False), hf_hub_download
    info = api.model_info(REPOSITORY, revision=base["revision"], files_metadata=True)
    if info.sha != base["revision"]:
        raise ValueError("Upstream metadata did not resolve to the pinned revision")
    remote = {item.rfilename: item for item in info.siblings}
    assets = sorted(REQUIRED_ASSETS | {name for name in ASSETS if (model / name).is_file()})
    pins, missing_bytes = {}, 0
    for name in sorted(set(assets) | set(shards)):
        item = remote.get(name)
        if item is None or type(item.size) is not int or item.size < 1:
            raise ValueError(f"Pinned upstream file/size unavailable: {name}")
        if item.lfs is not None:
            algorithm, digest = "sha256", item.lfs.sha256
            valid_digest = isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{64}", digest)
        else:
            algorithm, digest = "git_blob_sha1", item.blob_id
            valid_digest = isinstance(digest, str) and re.fullmatch(r"[a-f0-9]{40}", digest)
        if not valid_digest or (name in shards and algorithm != "sha256"):
            raise ValueError(f"Pinned integrity metadata unavailable: {name}")
        pins[name] = {"algorithm": algorithm, "digest": digest, "bytes": item.size}
        path = model / name
        if path.exists():
            if path.is_symlink() or not path.is_file() or path.stat().st_size != item.size or file_hash(path, algorithm) != digest:
                raise ValueError(f"Existing file differs from pinned upstream; refusing to overwrite: {name}")
        else:
            missing_bytes += item.size
    if shutil.disk_usage(model).free < missing_bytes + 2 * 1024**3:
        raise ValueError("Insufficient disk space: retain 2 GiB headroom beyond missing model files")
    for name, pin in pins.items():
        path = model / name
        if not path.exists():
            print(f"Restoring pinned {name} ({pin['bytes']} bytes)", flush=True)
            download(REPOSITORY, name, revision=base["revision"], local_dir=str(model), token=False)
        if (not path.is_file() or path.is_symlink() or path.stat().st_size != pin["bytes"]
                or file_hash(path, pin["algorithm"]) != pin["digest"]):
            raise ValueError(f"Restored file failed integrity verification: {name}")
    receipt = {"base_model": base, "files": pins, "verified_at": datetime.now(UTC).isoformat(),
               "scope": "File correspondence to the pinned public model, not model quality or security certification."}
    path = model / RECEIPT
    if path.exists():
        previous = json.loads(path.read_text())
        if previous.get("base_model") != base or previous.get("files") != pins:
            raise ValueError("A different receipt already exists; preserve it instead of overwriting")
    else:
        with path.open("x", encoding="utf-8") as handle:
            handle.write(json.dumps(receipt, indent=2) + "\n")
    return status(model)


def adapter_evidence(adapter: Path, base: dict) -> dict:
    run = json.loads((adapter.parent / "run.json").read_text())
    selection = json.loads((adapter / "selection.json").read_text())
    digest = file_hash(adapter / "adapters.safetensors")
    if (run.get("status") != "completed" or run.get("base_model") != base
            or digest != selection.get("checkpoint_sha256") or not run.get("config", {}).get("balance_per_bucket")
            or selection.get("validation_sha256") != run.get("fit_sha256", {}).get("valid")):
        raise ValueError("Adapter must match a completed property run and its recorded checkpoint selection")
    return {"path": str(adapter.resolve()), "sha256": digest,
            "selection": selection, "run_sha256": file_hash(adapter.parent / "run.json"),
            "config_sha256": file_hash(adapter / "adapter_config.json")}


def smoke(model_path: Path, adapter: Path | None = None) -> dict:
    readiness = status(model_path)
    if not readiness["ready_for_local_inference"]:
        raise ValueError("Model is not ready; restore/verify pinned files before inference")
    evidence = adapter_evidence(adapter, readiness["base_model"]) if adapter else None
    import mlx.core as mx
    from mlx_lm import generate, load
    from mlx_lm.sample_utils import make_sampler
    from mlx_lm.utils import get_total_parameters, load_adapters

    sys.path.insert(0, str(ROOT))
    from sentinel.modeling.properties import property_messages
    from sentinel.modeling.property_scoring import parse_property

    model, tokenizer = load(str(model_path))
    base_count = get_total_parameters(model)
    if not 1_400_000_000 <= base_count < 1_700_000_000:
        raise ValueError("Loaded model does not have approximately 1.5B logical base parameters")
    adapter_count = 0
    if adapter:
        model = load_adapters(model, str(adapter))
        adapter_count = sum(weight.size for weight in mx.load(str(adapter / "adapters.safetensors")).values())
    mx.random.seed(42)
    messages = property_messages(SMOKE_SOURCE, "107", "Example")
    prompt = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    prediction = generate(model, tokenizer, prompt=prompt, max_tokens=64, sampler=make_sampler(temp=0.0), verbose=False)
    parsed, error = None, ""
    try:
        parsed = parse_property(prediction, "107")
    except (ValueError, TypeError) as exc:
        error = str(exc)
    return {**readiness, "status": "candidate_only" if parsed is not None else "invalid_model_output",
            "base_parameter_count": base_count, "adapter_parameter_count": adapter_count,
            "adapter": evidence, "raw_prediction": prediction, "parsed_prediction": parsed, "parse_error": error,
            "smoke_source": SMOKE_SOURCE, "max_output_tokens": 64, "temperature": 0.0,
            "peak_memory_bytes": mx.get_peak_memory(), "created_at": datetime.now(UTC).isoformat(),
            "scope": "One engineering inference check, not training, a benchmark or a security accuracy claim. "
                     "The prior adapter failed its development gate. No dataset split, exploit, RPC or repair was accessed."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["status", "restore", "smoke"])
    parser.add_argument("--model", type=Path, default=Path("models/qwen-coder-1.5b-4bit"))
    parser.add_argument("--adapter", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--experimental", action="store_true")
    args = parser.parse_args()
    if args.output and args.output.exists():
        raise FileExistsError("Preserve earlier evidence; choose a new output path")
    if args.action == "smoke" and not args.experimental:
        raise SystemExit("Smoke inference requires --experimental; no model is a qualified security detector")
    if args.action == "smoke" and (platform.system() != "Darwin" or platform.machine() != "arm64"):
        raise SystemExit("This runtime requires Apple Silicon macOS")
    result = smoke(args.model, args.adapter) if args.action == "smoke" else restore(args.model) if args.action == "restore" else status(args.model)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as handle:
            handle.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    if not result["ready_for_local_inference"] or result.get("status") == "invalid_model_output":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
