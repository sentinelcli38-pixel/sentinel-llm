# Boolean-Decision Model Experiment

Status: the October 22, 2026 run completed but **failed** the development gate. The selected checkpoint predicts every validation case negative, missing all 22 positives. Precision is unavailable, not 100%. This adapter is not promoted or enabled in the product.

The subsequent [failure diagnostics](BINARY_MODEL_DIAGNOSTICS.md) verify the saved evidence, report score ordering, and measure source removal without tuning the threshold or treating missing code as safe.

## Frozen Development Plan

The goal is improved discrimination on the local 1.5B model, not a manufactured 99% result. The previous JSON-completion adapter predicted positive on 28 of 29 validation assessments. This experiment tests whether a different supervised objective helps: two-label cross entropy on the next `false` / `true` token, without spending the loss on a repeated JSON envelope. This is a hypothesis, not an established diagnosis of the prior failure.

Use the same restored 4-bit Qwen base at revision `b3252a2f97102b1fb1571fec2c9b27219a8536be`, starting from the unchanged base rather than either old adapter. Keep rank 8, four trainable layers, batch size 1, 1,024-token maximum, and gradient checkpointing. Freeze seed 211, learning rate 0.00003, 64 steps, checkpoints every 16 steps, and a decision threshold of 0.5; ties are negative. Do not search thresholds after seeing labels.

Preparation reads only the existing CGT `train.jsonl`, `valid.jsonl` and their manifest. Check revision, counts, file hashes, prompt/target schema, embedded source hashes, and train/validation disjointness of row IDs, raw normalized sources, clone components and lexical fingerprints. Do not open, hash, tokenize or evaluate any reserved model test file.

Within each property, sample equal numbers of unique positive and negative training rows, capped at 32 per label and limited by the smaller available label bucket. Do not oversample rare positives. For development validation, sample up to eight unique rows per label/property before training. Do not oversample or discard validation failures. Whole overlength examples are excluded and counted, not truncated. This selection is small and deliberately controlled; it is not representative production prevalence or a new untouched evaluation cohort.

The prompts explicitly request a Boolean without placing a labeled JSON example in the system instruction. The target is never included in inference inputs. Scores are preference between two token logits, not calibrated probabilities of a real vulnerability. Restricting the answer space guarantees a Boolean by construction; this does not demonstrate better free-form JSON generation.

The implementation uses MLX's existing model, LoRA conversion, automatic differentiation, optimizer and gradient-checkpointing helpers. To reduce memory, it applies the existing tied Qwen output head only to the final hidden state. Before training, verify that its two label logits match the public full model forward pass on a small probe. No transformer architecture, optimizer or Solidity security engine is reimplemented. Reference: [MLX LoRA documentation](https://github.com/ml-explore/mlx-lm/blob/main/mlx_lm/LORA.md); runtime APIs are checked against the installed pinned packages.

Compare the unchanged base and adapted model using the identical Boolean prompt, validation IDs and threshold. Evaluate after each checkpoint and select the lowest exact Boolean validation loss, using the earliest checkpoint for ties. Never select the checkpoint with the most flattering precision. Preserve every checkpoint and validation prediction. Compare with always-negative, always-positive and training-majority baselines; report actual training exposure rather than pretending all selected rows were seen.

The pre-existing development gate remains unchanged: perfect constructed output validity, balanced accuracy at least 0.65, recall at least 0.5, specificity at least 0.8, and accuracy greater than the strongest simple baseline. Passing only permits more research evaluation. For the 99% target, separately report observed precision, its 95% Wilson lower bound, recall of at least 80%, per-property precision bounds and the existing minimum 20 positives and 20 negatives per property. The small selected validation sample cannot establish that claim; `independent_claim_supported` remains false.

Intervals use [NIST's two-sided Wilson score formula](https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm). They are descriptive on this selected development sample. Independent-binomial and representative-sampling assumptions have not been established; lexical grouping does not prove semantic independence. A conditional token score of 0.99 is not 99% observed precision.

The original labels and existing experiments are never overwritten. Historical labels still need independent adjudication. The development validation pool has been available during earlier development, so this is not independent evidence and cannot replace a final external benchmark. The old JSON-completion results and the new restricted-label classifier use different protocols and are not a direct before/after accuracy comparison; only the base-versus-adapter comparison inside this experiment is controlled.

## Run

```bash
.venv-mlx/bin/python -u training/binary_mlx.py \
  --output training/runs/mac-binary-v1
```

The Make equivalent is `make model-train-binary`. To run a separately recorded replication, set a new path explicitly, for example `make model-train-binary BINARY_RUN_OUTPUT=training/runs/mac-binary-replication`. Earlier output directories are never overwritten.

Requires the restored local model, dedicated MLX environment, and Apple Silicon runtime. Existing output is refused. Select a new output directory for a distinct run; do not rerun with altered settings and overwrite earlier evidence. The runner performs no scanner, RPC, exploit, repair, dataset download, or model upload. It remains separate from Sentinel's default product workflow.

Outputs include `data-selection.json`, base validation predictions, all checkpoint predictions and weights, selected adapter metadata, training exposure/losses in `run.json`, and `comparison.json`. Keep the selected adapter tied to this Boolean-logit protocol; do not load it through the old JSON-generating `predict_mlx.py` and claim equivalent behavior.

## Measured Results

The completed run retained a 200-assessment unique training pool. All selected training labels were balanced within each property, without duplicating minority rows. The 64 actual updates saw 64 unique assessments: 37 positive and 27 negative. The balanced pool does not imply that a partial randomly ordered pass has perfectly balanced exposure or that every pool row was trained on.

| Property | Training positive / negative | Validation positive / negative |
| --- | ---: | ---: |
| Arithmetic, SWC-101 | 32 / 32 | 8 / 8 |
| Unchecked calls, SWC-104 | 32 / 32 | 8 / 8 |
| Reentrancy, SWC-107 | 29 / 29 | 5 / 8 |
| Origin authorization, SWC-115 | 7 / 7 | 1 / 8 |

The model kept 1,543,714,304 base parameters and updated 1,318,912 adapter parameters. Peak MLX allocation was approximately 1.84 GB, not a measurement of the Mac's total RAM consumption. The recorded training/evaluation phase took approximately six minutes, excluding initial model loading and preparation. No new dataset downloads, reserved test access, scanner execution, generated attacks, or model uploads occurred.

| Checkpoint | Boolean validation loss | TP | FP | TN | FN | Precision | Recall | Specificity |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Unchanged base | Not a selection candidate | 22 | 32 | 0 | 0 | 40.74% | 100% | 0% |
| Step 16 | 0.901809 | 22 | 32 | 0 | 0 | 40.74% | 100% | 0% |
| Step 32 | 1.227050 | 22 | 32 | 0 | 0 | 40.74% | 100% | 0% |
| Step 48 | 1.070456 | 22 | 32 | 0 | 0 | 40.74% | 100% | 0% |
| Step 64, selected | 0.667671 | 0 | 0 | 32 | 22 | Unavailable | 0% | 100% |

The predeclared minimum-loss rule selected step 64. Its accuracy is 32/54 (59.26%), exactly matching the always-negative and training-majority baselines. Both the base and selected model have 50% balanced accuracy. Constructed Boolean validity is 100% because the decoder chooses between two known labels; that is not a learned free-form output-quality improvement.

This run did not establish useful fixed-threshold discrimination. It shifted the hard-decision failure from all-positive to all-negative. Changed loss or removed false positives cannot justify reporting success while every positive is missed. The gate fails balanced accuracy, recall, and improvement over the strongest baseline. All 99% target indicators remain false. Even a perfect observed result on the available 22 positive validation labels could not establish the intended high-confidence, per-property 99% claim with these tiny denominators and reused development data.

The labels are unchanged. Do not tune a threshold to these already-inspected results, delete difficult cases, turn unknown external labels into negatives, or describe the selected model as certifying safety. Keep the old product behavior and earlier adapters unchanged. This result does not establish why discrimination failed; data quality/context, the objective, optimization schedule, and model capability remain hypotheses requiring controlled checks.

The next justified work is independently documented property labels and diverse positive/negative contrasts, plus a separate frozen external cohort with sufficient denominators. A subsequent training experiment should ensure meaningful exposure to the intended training data and assess whether the scores distinguish the two classes before considering calibration or broader use. Keep that as a separately recorded procedure; this run is not evidence that more steps alone will solve the task.

Evidence is in `training/runs/mac-binary-v1/`. The script used is archived at `reports/protocol-snapshots/binary-model-v1/training/binary_mlx.py`; its hash, the pinned base receipt, input train/validation hashes, selected adapter hash and actual exposure are recorded. All 65 frozen scanner code hashes remained unchanged. Verification passed 402 Python tests, five dashboard tests, targeted lint and whitespace checks. The broader suite includes existing reviewed local Forge fixtures; this model experiment itself executes no Solidity.
