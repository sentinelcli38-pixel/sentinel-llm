# Lexical Scale Control

## Fixed Procedure

The 54-case frozen-model experiment found a stronger lexical baseline than a 1.5B readout. Before treating its 80.77% precision as representative, check the same lexical method against the entire prepared validation split. This is a separate development experiment, not a way to claim the baseline is an LLM.

Prepare a fresh protocol before fitting. Use all **3,766 training** and **821 validation** assessments from the original pinned property dataset. No token-length fitting, case removal, resampling, label repair or test access is allowed. Fit one normalized-token unigram TF-IDF vectorizer per property exclusively on training sources, with at most 4,096 features. Keep the frozen experiment's scikit-learn 1.7.2 logistic regression settings: L2/liblinear, C=1, seed 419, tolerance 0.0001, at most 2,000 iterations, intercept, no class weighting, threshold 0.5 and negative ties. Abort on convergence failure.

Retain all 821 predictions and separately report the original 54-case cohort. The subset is declared by the old protocol's IDs, not chosen by new scores. These two reports overlap and are not independent replications. Training pool class proportions change naturally with expanded coverage; do not describe differences as attributable only to more sample count.

The full training split contains 453/212 arithmetic positives/negatives, 210/852 unchecked-call, 94/895 reentrancy, and 48/1,002 origin-authorization assessments. Full validation contains 126/36, 30/206, 14/170, and 11/228 respectively. This larger pool includes many sources excluded by the LLM experiment's 1,024-token budget. Historical assessments still need independent review and verified build context; no scanner compilation or Solidity execution is performed here.

## Run

```bash
.venv/bin/python training/lexical_scale.py prepare \
  --output training/runs/mac-lexical-scale-v1

.venv-mlx/bin/python training/lexical_scale.py score --experimental \
  --output training/runs/mac-lexical-scale-v1
```

Prepare requires the completed frozen-probe artifacts. Scoring requires the optional probe dependencies already installed in the MLX interpreter, but performs CPU-only lexical fitting and imports no Metal model. Existing outputs are refused. Code, dataset, full ID order, original probe and original validation subset are pinned. Classifier parameters, vocabulary and IDF are saved as JSON, never executable pickle.

No thresholds, regularization, class weights or vocabulary rules are tuned after looking at validation. Fitting more variations until one happens to achieve a flattering number would turn this split into an optimization target, not confirm a 99% claim. Reserved model test files remain unopened. Report counts, recall, specificity, precision uncertainty and failed gates, not only the most favorable percentage.

## Measured Results

Completed October 22, 2026. All 3,766 training assessments were used, and all 821 validation assessments retained. No LLM was trained or evaluated in this lexical-only stage.

| Cohort | TP / FP / TN / FN | Precision | Recall | Specificity | Accuracy |
| --- | --- | --- | --- | --- | --- |
| Full 821-case validation | 129 / 17 / 623 / 52 | 88.36% | 71.27% | 97.34% | 91.60% |
| Original 54-case subset | 10 / 2 / 30 / 12 | 83.33% | 45.45% | 93.75% | 74.07% |

The nominal full-cohort 95% Wilson precision interval is 82.14%-92.60%, not a 99% guarantee. This remains a non-random historical development cohort with correlated cases and unreviewed annotations; the interval does not remedy those limitations.

| Property | Positives / negatives | TP / FP / TN / FN | Precision | Recall |
| --- | --- | --- | --- | --- |
| SWC-101 | 126 / 36 | 123 / 17 / 19 / 3 | 87.86% | 97.62% |
| SWC-104 | 30 / 206 | 6 / 0 / 206 / 24 | 100% | 20% |
| SWC-107 | 14 / 170 | 0 / 0 / 170 / 14 | Unavailable | 0% |
| SWC-115 | 11 / 228 | 0 / 0 / 228 / 11 | Unavailable | 0% |

The larger unweighted training distribution yields a serious minority-property failure: every positive reentrancy and origin-authorization case is missed, and most unchecked-call positives are missed. The experiment changes both sample coverage and natural class proportions; this result is compatible with class-imbalance sensitivity but does not prove its sole cause. More raw assessments did not produce a reliable all-property detector.

The original aggregate development gate passes, illustrating its limited scope. It is **not** the requested 99%-precision/80%-recall gate and does not require useful recall within each property. Do not use that aggregate pass to promote this model. The new [precision target audit](PRECISION_TARGET_AUDIT.md) separately rejects this result, including these property failures, without rewriting the original gate or report. High aggregate accuracy and zero false positives in an all-negative property do not establish reliable detection.

Artifacts remain under `training/runs/mac-lexical-scale-v1/`: `protocol.json`, `classifiers.json` and `comparison.json`. The original 200-case lexical control and failed 1.5B readout remain separate; larger-scale results are not presented as LLM performance or cherry-picked replacement metrics.
