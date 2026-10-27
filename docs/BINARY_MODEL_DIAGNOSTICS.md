# Binary Model Failure Diagnostics

## Scope

The 64-step Boolean experiment failed its development gate. Before another training run, distinguish a fixed-threshold failure from weak score ordering and inspect source-input sensitivity. This diagnostic phase changes no weights, annotations, thresholds, checkpoints or product behavior. It uses existing train/validation evidence only and never opens reserved model test files.

The offline report verifies the frozen training implementation, every retained checkpoint hash, minimum-loss checkpoint selection, exact dataset pins, validation identities/labels, raw logits, saved decisions, reported metrics, losses, and actual training exposure. It recomputes positive/negative pair ordering, counting ties as half, as a descriptive ROC AUC. See [scikit-learn's ROC metric explanation](https://scikit-learn.org/stable/modules/model_evaluation.html#roc-metrics). No additional metrics dependency is installed: the small pair count is computed exactly with the standard library.

Interpret global ordering with caution: property mix can confound it, so retain per-property counts and score distributions. One positive `tx.origin` assessment cannot establish reliable population performance. Ranking is not precision, calibration, or proof of generalization. Missing labels are never inferred from warnings or absence of warnings.

## Frozen Ablation Plan

Before running new inference, fix seed 313 and select at most two existing validation cases per Boolean label/property. The selected subset is diagnostic, not a newly independent benchmark. Do not choose cases by their prediction quality. It contains at most 16 cases; the actual cohort has only one eligible positive SWC-115 case, so 15 cases are expected.

For the unchanged base and the selected step-64 adapter, use three prompt conditions:

- `full`: reproduce the original complete named-contract prompt and check its logits against the saved report.
- `without_source`: retain the original property and contract name, replacing code with an explicit source-withheld marker.
- `property_only`: withhold source and contract name; retain the requested property only.

Keep token budgets and label tokens unchanged. Cache identical property-only prompts within each model. Require successful reproduction of full-input logits within the declared numerical tolerance (absolute 0.05 plus relative 0.01 per logit). Reject overlength input rather than truncating it.

The two missing-source variants are **unassessable**, not clean contracts. They have unknown ground truth and are never added to accuracy/precision denominators. Report absolute score movement and fixed-threshold decision flips only. Differences can reflect prompt length, formatting, missing-context behavior, identifiers or code. They do not isolate semantic reasoning or show that a security conclusion is correct. Forcing two Boolean tokens also precludes an honest model abstention; do not treat those forced responses as assessments of missing source.

Keep these results separate from the original failure report. A score of 0.99 remains only a preference between two tokens, not 99% security precision. No threshold sweep or calibration is performed in this phase. Calibration would need a separate, documented procedure and cannot create reliable discrimination from an uninformative score.

## Run

```bash
.venv/bin/python training/diagnose_binary.py offline \
  --output training/runs/mac-binary-v1-diagnostics/offline.json

.venv-mlx/bin/python -u training/diagnose_binary.py ablate --experimental \
  --output training/runs/mac-binary-v1-diagnostics/source-ablation.json
```

Existing outputs are refused. The offline command requires no GPU. Ablation uses local Apple Silicon inference and the verified pinned model; there are no updates, downloads, RPC calls, Solidity execution, exploit generation, repairs or uploads. Saved hashes bind inputs at diagnostic time and do not retroactively authenticate unsigned historical files.

The Make equivalent for the offline audit is `make model-diagnose-binary BINARY_DIAGNOSTIC_OUTPUT=training/runs/mac-binary-v1-diagnostics/offline-rerun.json`. Use an unused output filename; a successful report is not a passing accuracy gate.

## Measured Findings

Completed October 22, 2026. All 54 validation cases were retained. Predictions, original labels, metrics, checkpoint losses and selection, actual training exposure, retained checkpoint weights, and frozen train/validation pins were verified. The base and selected adapter were not retrained or recalibrated.

| Property | Positives / negatives | Base pair ordering | Adapted pair ordering |
| --- | ---: | ---: | ---: |
| Arithmetic | 8 / 8 | 0.656250 | 0.796875 |
| Unchecked calls | 8 / 8 | 0.359375 | 0.289063 |
| Reentrancy | 5 / 8 | 0.700000 | 0.725000 |
| Origin authorization | 1 / 8 | 0.250000 | 0.250000 |
| Overall | 22 / 32 | 0.681108 | 0.607955 |

Overall ordering worsened after fine-tuning, although individual properties differ. The selected adapter's positive-label scores range from approximately 0.323 to 0.440; negative-label scores range from 0.306 to 0.430. Both are below the fixed 0.5 threshold and overlap substantially. Mean adapted scores are approximately 0.388 for positives and 0.376 for negatives. These are conditional token preferences, not calibrated security probabilities.

The adaptation shifted the true-minus-false logit margin by an average of -2.733, with standard deviation 0.157. This is compatible with a substantial global decision-bias shift, but is not proof that only a global bias changed or an identified cause of failure. Do not choose an aggregate threshold after inspecting these results, flip the unchecked-call labels or score direction to improve a chart, or treat property-specific tiny-sample ordering as an accuracy claim.

The predeclared source experiment sampled 15 validation cases and evaluated the original and two missing-context conditions for both models. Original-input logits reproduced the saved reports within the fixed numerical tolerance.

| Model | Removed context | Mean absolute score movement | Decision flips |
| --- | --- | ---: | ---: |
| Base | Source code | 0.127315 | 0 / 15 |
| Base | Source and target name | 0.109566 | 0 / 15 |
| Adapted | Source code | 0.135027 | 0 / 15 |
| Adapted | Source and target name | 0.125226 | 0 / 15 |

Scores do respond to these input changes; it would be incorrect to conclude that the model literally ignores the source. At the current operating point, however, the sampled hard decisions remain all-positive for the base and all-negative for the adapter even with source withheld. No-code conditions are unknown/unassessable and were never scored as clean cases. This diagnostic does not establish semantic reasoning, explain every failure, or justify deployment.

Reports are in `training/runs/mac-binary-v1-diagnostics/offline.json` and `source-ablation.json`. Existing training artifacts, labels, and default product behavior are unchanged. Verification passed 423 Python tests, five dashboard tests, targeted lint and whitespace checks. Native inference was local; the broader suite includes pre-existing reviewed local Forge fixture tests, not attacks against benchmark contracts. Reserved model tests remain unopened.

## Next Work

Prioritize a property-specific source/context and label audit, especially the poorly ordered unchecked-call cases, while retaining the entire intended evaluation denominator. Independent reviewers should document positive and negative assessments against the named contract, compiler-era behavior and required dependencies, not approve only the model's warnings. Any independently justified relabeling belongs in a new manifest with provenance.

The [model-label review preparation](MODEL_LABEL_REVIEW.md) now implements that handoff: complete validation coverage, a separate training-only packet, deterministic contrast candidates, and blank independent reviewer forms. It does not establish compiled context or complete human adjudication.

Build diverse, reviewed positive/negative training contrasts and define the next training procedure before measuring it. If investigating calibration, use a separately declared training-side calibration protocol and a frozen assessment set; do not search these inspected validation scores for a flattering precision. Preserve all missed positives, invalid inputs and review-required cases. A model still needs to beat simple baselines and pass independent external assessment before any credible 99% precision claim.

