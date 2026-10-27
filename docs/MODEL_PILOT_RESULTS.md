# Apple Silicon fine-tuning pilot

## Run details

Completed October 13, 2026 on an Apple M3 Mac with 8 GB unified memory. The
training process completed with exit code 0 and saved a usable LoRA adapter.
No cloud GPU was used.

| Setting | Value |
| --- | --- |
| Base model | mlx-community/Qwen2.5-Coder-1.5B-Instruct-4bit |
| Base revision | b3252a2f97102b1fb1571fec2c9b27219a8536be |
| Corpus revision | 230e649123477eff332742a59a1c7cc6dc286cab |
| Base parameters reported by MLX | 1,543.714 million |
| Trainable adapter parameters | 1.319 million (0.085%) |
| Training iterations | 10 |
| Fitted train / validation / test cases | 79 / 9 / 11 |
| Sequence limit / batch size | 1,024 tokens / 1 |
| Seed / LoRA rank / trainable layers | 42 / 8 / 4 |
| Initial / final validation loss | 2.002 / 0.173 |

Validation loss used two validation batches, not the entire validation split.
The 97 / 10 / 15 prepared splits became 79 / 9 / 11 after excluding whole
examples over the token budget. Another 21 cases were excluded because they
belong to previously inspected source groups. The fitted test SHA-256 is
`6285387f01f5f9d598ba294892a2683be2fcdedd50704a3c0ec59fabc3d6dc38`.

## Held-out results

Both model evaluations used the same 11 contracts, greedy decoding, and a
256-token output limit. The base model returned empty findings for every case.

| Metric | Base model | Sentinel adapter |
| --- | --- | --- |
| Annotated category recall | 0 / 11 (0%) | 5 / 11 (45.45%) |
| Category with overlapping annotated line | 0 / 11 (0%) | 2 / 11 (18.18%) |
| Schema-valid JSON | 11 / 11 (100%) | 11 / 11 (100%) |

An always-predict-`unchecked_low_level_calls` baseline, selected from training
labels only, also achieves 5 / 11 category matches. The adapter predicts that
category in eight cases and `denial_of_service` in three. It therefore has not
demonstrated category-detection performance beyond a simple majority-label
heuristic. Schema-valid output is not evidence that a finding is correct.

A direct inference smoke test on the provided vulnerable reentrancy fixture
also completed, but predicted the wrong category. The inference command works;
its answer must not be presented as a verified assessment.

## Interpretation and next experiment

This pilot establishes local training and inference feasibility, not dependable
security detection. It is not evidence of zero-day detection, novelty relative
to commercial products, or production readiness. Precision, F1, specificity,
and false-positive rate are not reported because reviewed clean controls and
complete annotation are absent. The small historical test set also cannot
establish generalization or exclude base-model pretraining contamination.

The next experiment should add independently reviewed clean and vulnerable
contracts, balance training categories, audit semantic clones, and compare
against scanner and majority-label baselines. Select training settings using
validation only. Keep this pilot's test results archived and use a new untouched
test set for confirmatory claims after further development. Do not use the
adapter to approve repairs or replace executable validation.

## Local evidence

- `training/runs/mac-pilot/run.json`: configuration, provenance, package versions,
  dataset hashes, timestamps, and exit status.
- `training/runs/mac-pilot/training.log`: full training output.
- `training/runs/mac-pilot/adapter/adapters.safetensors`: trained weights.
- `training/runs/base-predictions.jsonl`: original-model predictions.
- `training/runs/adapter-predictions.jsonl`: adapted-model predictions.
- `training/runs/pilot-comparison.json`: matched-case comparison and baseline.

Generated datasets, model weights, and run artifacts stay local and are ignored
by Git. See [setup and commands](MODEL_TRAINING.md) to reproduce the workflow.
