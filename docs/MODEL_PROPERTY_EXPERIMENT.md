# Balanced property-classification experiment

The first completed run fails the development gate. Read the
[measured results](MODEL_PROPERTY_RESULTS.md) before using its adapter.

This second local experiment uses [Consolidated Ground Truth (CGT)](https://github.com/gsalzer/cgt),
a consolidation of published manually assessed vulnerability properties.
Sources and annotations are pinned at `f8cd72cf7fbbfebc809c454667eee271706a4b2b`.
An assessment marked false establishes only the absence of its assessed weakness,
not that the whole contract is safe. The experiment covers SWC-101 (arithmetic),
SWC-104 (unchecked call returns), SWC-107 (reentrancy), and SWC-115 (`tx.origin`
authorization). It does not train general access-control detection from negative
`tx.origin` labels.

## Reproduction

Use the separate `.venv-mlx` environment from [the first training guide](MODEL_TRAINING.md).
From the repository root:

```bash
make fetch-cgt
make model-prepare-properties
make model-audit-properties
make model-train-properties
make model-select-properties
make model-validate-properties-base
make model-validate-properties-adapter
make model-compare-properties
```

Preparation refuses to overwrite an existing dataset. Training and evaluation
refuse to overwrite existing weights or prediction files. For another experiment,
copy the configuration, use distinct prepared/fitted data and adapter paths, and
record new output files. Do not overwrite the first pilot's datasets or adapter.

## Label and split safeguards

- The importer retains each original dataset, entry, property and assessment.
- Assessments of the same target contract and SWC must agree; conflicting labels
  are excluded rather than selected according to model performance.
- Comments are removed while strings and code are retained. Labels, paths, and
  upstream entry identifiers are never placed in the model prompt.
- Sources sharing compiler-independent source fingerprints, deployment/runtime
  fingerprints, chain addresses, or upstream entry identities stay together.
- Identifier/literal-normalized token fingerprints and five-token shingle Jaccard
  similarity at 0.85 form connected clone components before any split.
- All 143 original SmartBugs sources participate in the clone audit. Any component
  connected to them is excluded, not reassigned to another split.
- Components, rather than individual assessments, are split deterministically
  with seed 73. Audits reject cross-split groups, sources, normalized fingerprints,
  and row identities, as well as changed file hashes and manifest counts.

This is conservative lexical screening, not proof of semantic independence.
Contract and function names may still reveal task information, and historical
sources may be in the base model's pretraining corpus. Independent label review
and a contemporary external benchmark are still needed for strong claims.

## Mac-sized training

`training/mac-properties.yaml` starts from the original quantized 1.5B model,
not the first pilot adapter. It uses 80 steps, four trainable layers, rank 8,
batch size 1, gradient checkpointing and a 1,024-token sequence budget.

Whole examples over the budget are excluded. Only training data is balanced:
each SWC/Boolean bucket contributes 16 rows. Minority rows may repeat, and the
manifest reports unique and repeated counts. Repetition is not new data.
Validation and test subsets use at most four unique assessments per bucket,
chosen before training; neither split is oversampled. These deliberately limited
subsets are a development experiment, not an estimate of real-world prevalence.
The complete prepared splits remain archived locally for broader experiments.

Training uses all selected validation cases when reporting validation loss.
Checkpoint selection uses the lowest reported validation loss, choosing the
earliest step on rounded-loss ties. It copies the selected weights to a separate
directory, records their hash and selection evidence, and never reads test data.
The run, balance counts, exclusions, hashes, versions and loss logs are written
to `training/runs/mac-properties/`. The new test split stays untouched during
validation-based development.

## Scoring and the development gate

Predictions must contain exactly `swc` and a Boolean `vulnerable`. Strings such
as `"false"`, another SWC code, extra fields and malformed JSON are invalid.
Reports include per-property confusion counts, precision, recall, F1, specificity,
balanced accuracy, observed false-positive rate, validity and accuracy.
Invalid answers never count as true negatives: they reduce accuracy/specificity
or recall and are shown separately. `negative_error_rate` includes both invalid
negative cases and observed false positives; observed false-positive rate alone
is not an adequate measure when outputs are invalid.

The same validation cases are compared with the base model, always-negative,
always-positive and training-only per-property majority baselines. The gate
requires valid output in every case, balanced accuracy at least 0.65, positive
recall at least 0.5, specificity at least 0.8, and accuracy exceeding the strongest
simple baseline. Thresholds are fixed before evaluating the trained adapter.
Passing permits further research evaluation only, not production promotion.
The test split is not used to select hyperparameters or repair poor validation.

## Inference

```bash
.venv-mlx/bin/python training/predict_mlx.py \
  examples/vulnerable_reentrancy/src/VulnerableVault.sol \
  --task swc_property --swc 107 --contract VulnerableVault \
  --adapter training/runs/mac-properties/selected-adapter --experimental
```

Inference is blocked without the explicit research-only `--experimental` opt-in because this adapter failed its validation gate. These are candidate-only assessments. The property adapter cannot provide source
locations or certify that a repair is safe, and it remains outside the production
scan workflow. Do not replace Slither, Mythril, Forge, or human review with it.

CGT's Solidity sources retain their individual source licenses. Its repository
license is not blanket permission to redistribute all source contracts or trained
artifacts. Preserve provenance, cite the original datasets and CGT's accompanying
paper, and review licenses before publication. Generated data and model weights
remain ignored by Git.
