# CGT property experiment: measured results

Completed October 13, 2026 using only the Apple M3 Mac with 8 GB memory.
The new model is still experimental and fails its development quality gate.

## Data and training

CGT revision: `f8cd72cf7fbbfebc809c454667eee271706a4b2b`.
Base model revision: `b3252a2f97102b1fb1571fec2c9b27219a8536be`.

After target validation and conflicting-label exclusions, 5,441 property
assessments were assigned to training, validation and test splits. A further
122 assessments were excluded through clone/identity connections with the
143 original SmartBugs sources. The importer skipped 165 conflicting target/SWC
labels and two assessments without a usable target contract.

The clone audit examined 2,115 sources, formed 1,330 components and found 3,511
near-clone links. These numbers describe lexical screening and identity grouping,
not proof of semantic independence.

| Split | Prepared assessments | Fit 1,024 tokens | Selected for this run |
| --- | --- | --- | --- |
| Training | 3,766 | 2,075 | 128 rows, 119 unique |
| Validation | 821 | 538 | 29 unique |
| Reserved test | 854 | 482 | 28 unique, not evaluated |

The training pool has 16 rows for each of eight SWC/Boolean buckets. Nine rows
are repeats from the small positive SWC-115 bucket. Training completed 80
single-example steps with rank-8 LoRA over four layers; this does not imply that
all 119 unique pool examples were seen. It updated 1.319 million adapter
parameters in the 1.5-billion-parameter quantized base.

Initial validation loss was 1.918. Reported checkpoint losses were 0.046 at
step 20, 0.039 at steps 40 and 60, and 0.083 at step 80. The earliest minimum
reported loss selected step 40. Selection used only validation, never test.
All original and new checkpoints remain archived locally.

## Validation results

Both evaluations used the identical 29 property assessments, comprising 13
positive and 16 negative labels, greedy decoding and a 64-token output limit.
These are property assessments, not necessarily 29 independent contracts.

| Metric | Base model | Selected step-40 adapter |
| --- | --- | --- |
| Accuracy | 11 / 29 (37.93%) | 14 / 29 (48.28%) |
| Balanced accuracy | 42.31% | 53.13% |
| Positive recall | 11 / 13 (84.62%) | 13 / 13 (100%) |
| Specificity | 0 / 16 (0%) | 1 / 16 (6.25%) |
| Observed false positives | 12 / 16 (75%) | 15 / 16 (93.75%) |
| Invalid answers | 6 / 29 | 0 / 29 |
| Precision | 47.83% | 46.43% |
| F1 | 61.11% | 63.41% |

The base model also had four invalid answers on negative cases. Its total
negative error rate was therefore 100%; invalid answers are not true negatives.
The adapter returned the correct output schema but predicted positive on 28 of
29 cases. Its perfect positive recall is consequently not evidence of reliable
discrimination.

The always-negative and training-majority baselines both achieve 16 / 29
accuracy (55.17%) and 50% balanced accuracy. Always-positive achieves 13 / 29
accuracy (44.83%) and 50% balanced accuracy. The adapter does not exceed the
strongest baseline's accuracy, and its balanced accuracy is only slightly above
chance on this small, deliberately selected validation set.

The development gate fails balanced accuracy, specificity and improvement over
the strongest baseline. Do not deploy this adapter as a detector, treat its
negative output as a safety certificate, or use it to approve patches.
It remains separate from Sentinel's scan/repair/Judge workflow.

## Reserved evidence and further work

The new test split has not been evaluated. Its fitted SHA-256 is
`e77f4c8d8a4101b3d16aa7b7fe759683ebc165f357792698b88e750a0ef77a5e`.
Validation SHA-256 is
`8579b82947d31731546af90066f3da09fc900260d8ef1a44cbadb849591a54cc`.

The next development experiment should address the positive-output bias using
more diverse unique negative/positive contrasts and validation-guided changes
to the supervised objective or sampling. Longer training alone is not a
justification: the final checkpoint already had worse validation loss. Broader
scanner comparisons, independent contemporary labels and per-property external
evaluation remain necessary. Use the reserved test for confirmation only after
fixing a candidate procedure, not as a source of tuning feedback.

Local evidence is under `training/runs/mac-properties/`: `run.json`,
`training.log`, all adapter checkpoints, `selected-adapter/selection.json`,
`base-valid.jsonl`, `adapter-valid.jsonl`, their summary files, and
`validation-comparison.json`. Generated data and weights are ignored by Git.
See [setup and safeguards](MODEL_PROPERTY_EXPERIMENT.md).
