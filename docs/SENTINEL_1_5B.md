# Sentinel 1.5B Local Model

## What We Have

Sentinel uses a 4-bit MLX conversion of Qwen2.5-Coder-1.5B-Instruct. On October 22, 2026, local inference verified **1,543,714,304 logical base parameters**. Quantization reduces storage and memory use, not the architecture's parameter count. The original [Qwen model card](https://huggingface.co/Qwen/Qwen2.5-Coder-1.5B-Instruct) describes this as a 1.54B-parameter model.

The existing Sentinel property adapter was trained locally on October 13, 2026 using rank-8 LoRA over four layers. Its training log reports approximately 1.319M trainable parameters; the restored runtime counted **1,318,912 adapter parameters**. This is domain-specific fine-tuning of an existing 1.5B base, not pretraining a new foundation model or updating all 1.5B weights. MLX supports this approach through [quantized LoRA fine-tuning](https://github.com/ml-explore/mlx-lm/blob/main/mlx_lm/LORA.md).

The parameter-count goal has been achieved. **Reliable vulnerability detection has not.** The previous adapter failed its validation gate, with 46.43% observed precision and 6.25% specificity on 29 validation property assessments. It remains research-only and outside the trusted scanner/repair/Judge workflow. A larger parameter count does not establish 99% precision.

## Locations

- Base: `models/qwen-coder-1.5b-4bit/`.
- Pinned conversion revision: `b3252a2f97102b1fb1571fec2c9b27219a8536be`.
- Selected Sentinel adapter: `training/runs/mac-properties/selected-adapter/`.
- Original training record and checkpoints: `training/runs/mac-properties/`.
- New readiness evidence: `training/runs/model-readiness-20261022/`.

The base weight file had been missing while its tokenizer and metadata remained present. The readiness tool restored the 868,628,559-byte weight file from the same pinned public revision and checked its upstream SHA-256. Existing tokenizer/configuration files were also checked against pinned upstream Git blob hashes. `sentinel-weights.json` records that correspondence. This proves file correspondence, not dataset provenance, historical weight identity beyond the recorded revision, or model quality.

## Step 1: Check Readiness

From the repository directory:

```bash
make model-local-status
```

This verifies required files and their receipt hashes. It needs no GPU, accesses no dataset split, and never treats file presence alone as proof of integrity. `ready_for_local_inference: true` means the files are ready, not that predictions are trustworthy.

If weights go missing again:

```bash
make model-local-restore
```

Restoration uses the dedicated `.venv-mlx` environment and downloads only missing files from the existing pinned revision. It refuses to overwrite modified files and retains 2 GiB of disk headroom beyond the missing download size. It does not select a newer model version or retrain an adapter.

## Step 2: Run A Local Inference Check

```bash
make model-local-smoke
```

This loads the 1.5B base and selected adapter on Apple Silicon, verifies recorded adapter/base correspondence, counts parameters, and generates a bounded answer for an inline example. The command explicitly opts into experimental inference. It does not read training, validation, or reserved test data, and does not execute Solidity.

For the base without an adapter, or to retain a new non-overwriting report:

```bash
.venv-mlx/bin/python training/local_model.py smoke --experimental \
  --output training/runs/model-readiness-20261022/base-rerun.json

.venv-mlx/bin/python training/local_model.py smoke --experimental \
  --adapter training/runs/mac-properties/selected-adapter \
  --output training/runs/model-readiness-20261022/adapter-rerun.json
```

Successful loading and valid JSON prove only that the runtime works. Inspect the prediction: the inline pure getter has no external calls and should not be flagged as reentrant. The restored base nevertheless predicted `vulnerable: true`. This observed false alarm reinforces the existing quality warning; do not turn a successful smoke command into a security-accuracy claim.

The selected adapter returned `vulnerable: false` on that same inline example. Both outputs are retained in `base-smoke.json` and `adapter-smoke.json`; the restoration record is `restoration.json`. This one engineering example is not an independent evaluation and does not override the failed 29-assessment validation gate. No new training was performed during restoration.

## Step 3: Inspect A Solidity File

The existing inference script accepts a named contract and property:

```bash
.venv-mlx/bin/python training/predict_mlx.py \
  examples/vulnerable_reentrancy/src/VulnerableVault.sol \
  --task swc_property --swc 107 --contract VulnerableVault \
  --adapter training/runs/mac-properties/selected-adapter --experimental
```

Outputs are untrusted candidates. `vulnerable: false` concerns only the requested property and is not a safety certificate. Sources over the local 1,024-token input budget are rejected rather than silently truncated. These predictions must not approve deployments, patches, or transactions.

## Step 4: Improve The Model, Not Its Claimed Size

The next development experiment should address the observed positive-output bias. Use more diverse, unique positive and negative training contrasts; preserve compiler/contract context and property-specific label scope; avoid multiplying rare examples and calling repetitions new data. Compare against the unchanged base and simple baselines on a frozen validation cohort. Preserve earlier weights and scores.

The [Boolean-decision experiment](BINARY_MODEL_EXPERIMENT.md) now implements a train/validation-only path and tests a restricted-label loss. Its completed first run also fails: the selected model predicts every validation case negative. It is retained as failed research evidence, not substituted for the older adapter or enabled as a 99% detector.

Select training settings and checkpoints using development evidence only. Reserved model test files remain sealed; the new readiness and Boolean-training tools never open them. Existing legacy fitting commands process multiple prepared splits, so do not invoke them merely to repair weights or inspect readiness. Use the separately audited train/validation-only path for further development.

Only consider broader integration after demonstrating useful specificity, recall, validity and baseline improvement, followed by independent external evaluation. More iterations or a lower JSON-completion loss alone do not establish semantic learning. Independent review and an adequately sized, representative benchmark remain necessary for credible accuracy claims.

For the academic report, an accurate description is: "Sentinel uses an experimental, domain-adapted 1.5B code language model through quantized LoRA fine-tuning." Attribute Qwen and MLX, cite the original datasets, retain source licenses, and do not describe the model as pretrained from scratch or trained on billions of labeled contracts. Model and dataset weights remain ignored by Git; nothing was uploaded.

See [training setup](MODEL_TRAINING.md) and [measured property results](MODEL_PROPERTY_RESULTS.md).

Verification of this readiness workflow passed 377 Python tests, five dashboard tests, targeted lint, and whitespace checks. The broader Python suite includes existing reviewed local Forge fixtures; the new model smoke tests themselves execute no Solidity, exploit, patch, or live RPC call. All 65 frozen scanner implementation hashes remain unchanged.
