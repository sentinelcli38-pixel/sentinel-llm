# Sentinel model training on Apple Silicon

The local pilot adapts a 4-bit Qwen2.5-Coder-1.5B-Instruct model with MLX LoRA. It trains a small set of adapter weights while retaining the billion-parameter base model. This is supervised fine-tuning, not pretraining a foundation model. It learns annotated vulnerability categories and original source line numbers. Repair synthesis and exploit verification remain separate Sentinel capabilities.

For the current installed model, weight restoration, actual parameter verification, and safe local inference commands, start with [Sentinel 1.5B readiness](SENTINEL_1_5B.md). The base was restored and verified on October 22, 2026; the existing adapters remain unqualified. Readiness checks do not open any dataset split. The legacy fitting workflow below processes prepared splits and must not be used merely to check whether weights are installed.

The newer [Boolean-decision experiment](BINARY_MODEL_EXPERIMENT.md) uses a train/validation-only reader, unique balanced training examples, and a two-label loss. It preserves the older JSON-completion adapters and all reserved test data. Its restricted-label outputs are a different inference protocol, not a drop-in replacement for the older adapter.

## Setup

Run these commands from the Sentinel repository root. Python 3.11 and Apple Silicon are required for the dedicated environment; the CLI/API environment remains separate.

```bash
python3.11 -m venv .venv-mlx
.venv-mlx/bin/python -m pip install -r training/requirements-mac.txt
make fetch-smartbugs-curated
make model-prepare
make model-audit
make model-download
make model-train
make model-evaluate-base
make model-evaluate-adapter
make model-compare
```

The download resolves and records the Hugging Face revision. Training metadata, command, package versions, dataset hashes, status, and loss logs are saved in `training/runs/mac-pilot/`. The adapter is saved in `training/runs/mac-pilot/adapter/`. Base weights stay in `models/qwen-coder-1.5b-4bit/`. All generated data and model weights are ignored by Git.

## Memory budget

`training/mac-8gb.yaml` uses batch size 1, four trainable layers, rank 8, gradient checkpointing, and a 1,024-token limit. The default is a 10-iteration pilot. Close memory-heavy apps before running it. Preparation excludes whole examples that exceed the token limit, and records the excluded counts; it never truncates away the supervised answer. Memory use depends on OS and other applications. A pilot confirms whether the configuration fits this Mac before a longer experiment.

For a longer run, copy the YAML to a new file, change `iters` and `adapter_path`, then run:

```bash
.venv-mlx/bin/python -u training/run_mlx.py --config training/my-run.yaml
```

The runner refuses to overwrite an existing adapter. Evaluation also refuses to overwrite earlier prediction files. Compare the same frozen test file and decoding budget for the base and adapted models. Increasing steps or lowering training loss does not by itself establish better vulnerability detection.

## Dataset and research scope

The importer retains corpus revision, source paths, original URLs, source hashes, and labels. It removes source comments to prevent annotation leakage while retaining line positions and string literals. Repository groups stay in a single split. Exact duplicates are removed. Sources related to the four previously inspected SmartBugs starter cases are excluded from training, validation, and testing. The manifest lists counts and hashes for each split; `model audit` checks them before training.

This small, historical corpus is a pipeline pilot. Source grouping and exact deduplication do not eliminate every semantic clone or unknown base-model pretraining overlap. Names in historical vulnerable examples may still reveal task information. Add contemporary audited projects, independently reviewed clean controls, and a broader clone audit before claiming generalization.

Contracts keep their individual source licenses. Preserve the dataset manifest and attribution, and review applicable licenses before redistributing data or trained artifacts.

## Evaluation

`training/evaluate_mlx.py` generates answers from the prompt alone. It stores raw predictions and scores category recall, category-plus-line recall, and JSON validity. A category match requires the annotated vulnerability category. Localization additionally requires an overlapping original source line. Invalid outputs count as misses. Precision and F1 remain unavailable for this positive-only pilot.

`training/compare_mlx.py` verifies that both prediction files refer to the same frozen test cases and compares them with an always-predict-most-common-category baseline selected only from training labels. See [measured pilot results](MODEL_PILOT_RESULTS.md) for the first local run.

The trained adapter is for the detection task. It is evaluated separately from the production scan workflow until accuracy and failure behavior have been measured. Do not replace the Forge Judge with an LLM confidence score.

For the next balanced positive/negative experiment, see [CGT property training](MODEL_PROPERTY_EXPERIMENT.md).
Its targets are property-level Booleans rather than invented source locations.
The first adapter and frozen pilot results remain separate.

No local model has passed qualification. Single-contract inference is blocked by default; explicitly opt into untrusted research predictions:

```bash
.venv-mlx/bin/python training/predict_mlx.py examples/vulnerable_reentrancy/src/VulnerableVault.sol --adapter training/runs/mac-pilot/adapter --experimental
```

Predictions remain candidates requiring review and executable validation. Invalid output or out-of-range locations produce a failed prediction, not an assessment of safety.

References: [MLX LoRA guide](https://github.com/ml-explore/mlx-lm/blob/main/mlx_lm/LORA.md), [quantized base model](https://huggingface.co/mlx-community/Qwen2.5-Coder-1.5B-Instruct-4bit), [SmartBugs Curated](https://github.com/smartbugs/smartbugs-curated).
