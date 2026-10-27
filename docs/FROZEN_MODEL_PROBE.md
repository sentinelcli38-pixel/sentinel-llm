# Frozen Model Readout Experiment

## Fixed Plan

The prior 64-step adapter collapsed to all-negative decisions. Before further adapter tuning, test whether a small property-specific classifier can use the unadapted 1.5B model's representations. This is a **development diagnostic on historical unreviewed labels**, not a substitute for the pending expert review or an independent accuracy claim.

Freeze the procedure before extracting features or fitting classifiers:

- Use exactly the original binary experiment's 200 selected training and 54 validation assessments, in frozen ID order. Do not truncate, resample, drop failed inputs or open reserved model tests.
- Use the verified pinned 4-bit Qwen base, with no adapters and no base-weight updates. Extract the 1,536-dimensional final prompt-token hidden state using the original neutral Boolean prompt, never an assistant answer. L2-normalize each feature row without fitting validation statistics.
- Fit one binary L2-regularized logistic regression per property using scikit-learn 1.7.2, `liblinear`, `C=1`, tolerance 0.0001, maximum 2,000 iterations, intercept enabled, no class weighting and seed 419. Abort on convergence failure.
- Keep the decision threshold at 0.5, ties negative. No threshold search, calibration, checkpoint selection, feature selection based on validation, or hyperparameter search.
- Fit a lexical control using the same classifiers and training cases: per-property normalized-token unigram TF-IDF, maximum 4,096 features, vocabulary and IDF fitted only on training sources. Lexical tokens are a control, not a Solidity parser.
- Retain and report both methods. Do not select whichever has a flattering validation number. Preserve every validation case, training resubstitution metrics, per-property counts, precision uncertainty and simple baselines.

The model's original base validation logits must reproduce within the previously fixed tolerance (absolute 0.05 plus relative 0.01 per logit). Exported features, order, prompts, model assets, source-run evidence and protocol implementation are hash-pinned. Classifier coefficients and lexical preprocessing are stored as JSON, not executable pickle files. These checks establish local artifact consistency, not authenticated historical authorship.

All 200 selected training assessments enter readout fitting, unlike the old 64-step adapter run that saw only 64 unique examples from its 200-case pool. The frozen model has 1,543,714,304 logical base parameters; only 6,148 new readout coefficients/intercepts (four times 1,537) are fitted. More training exposure and a different classifier are jointly changed, so this is not a controlled attribution of improvement to one cause. Neither method's training-resubstitution metrics are evidence of generalization.

The classification implementation uses the documented [LogisticRegression estimator](https://scikit-learn.org/1.7/modules/generated/sklearn.linear_model.LogisticRegression.html) and [TfidfVectorizer](https://scikit-learn.org/1.7/modules/generated/sklearn.feature_extraction.text.TfidfVectorizer.html). No handwritten optimization engine or changes to production dependencies are needed. Classifier scores are not calibrated security probabilities, and probe fitting does not train all 1.5 billion base parameters.

## Run

```bash
.venv-mlx/bin/python -m pip install -r training/requirements-probe.txt

.venv/bin/python training/frozen_probe.py prepare \
  --output training/runs/mac-frozen-probe-v1

.venv-mlx/bin/python -u training/frozen_probe.py extract --experimental \
  --output training/runs/mac-frozen-probe-v1

.venv-mlx/bin/python training/frozen_probe.py score --experimental \
  --output training/runs/mac-frozen-probe-v1
```

Existing stage artifacts are refused. An interrupted extraction without `features.json` is incomplete, not a successful result. Prepare a new run directory rather than replacing prior evidence. No benchmark Solidity is executed, no exploit or patch is generated, no RPC is contacted, and no model test file is read.

Even a 99% point estimate on 54 already-inspected development assessments would not support a broad 99% precision claim. The current cohort has only one positive origin-authorization assessment. Independent expert labels, build context, adequate sample support, recall/coverage constraints and external validation remain prerequisites. Do not lower recall requirements or selectively report a small property to declare the overall target met.

## Measured Results

Completed October 22, 2026, on the local Mac. All 200 training and 54 validation cases were retained; every original base validation logit reproduced within the fixed tolerance. Extraction took approximately four minutes 35 seconds and peaked at 1.60 GB reported MLX allocation, not whole-process/system memory. No base weights or old adapters changed.

| Method, 54 cases | TP / FP / TN / FN | Precision | Recall | Specificity | Accuracy |
| --- | --- | --- | --- | --- | --- |
| Prior step-64 adapter | 0 / 0 / 32 / 22 | Unavailable | 0% | 100% | 59.26% |
| Frozen Qwen readout | 15 / 11 / 21 / 7 | 57.69% | 68.18% | 65.63% | 66.67% |
| Lexical control | 21 / 5 / 27 / 1 | 80.77% | 95.45% | 84.38% | 88.89% |

Training-resubstitution accuracy is 80% for the readout and 87% for the lexical control; these are not independent performance estimates. Validation descriptive ROC AUC is 0.6861 and 0.9418 respectively. The readout fails the existing development gate on specificity; the lexical control passes that limited development gate but is neither a qualified detector nor a 99% model.

| Property | Readout precision / recall | Lexical precision / recall |
| --- | --- | --- |
| SWC-101 | 50% / 62.5% | 88.89% / 100% |
| SWC-104 | 85.71% / 75% | 100% / 100% |
| SWC-107 | 60% / 60% | 66.67% / 80% |
| SWC-115 | 25% / 100% | 33.33% / 100% |

Unchecked-call lexical precision is 8/8 positive predictions on a small historical development subset, not evidence of 99% general precision. Origin authorization has only one positive case. Do not cherry-pick one property or training-resubstitution score to describe the entire product.

Nominal two-sided 95% Wilson precision intervals are approximately 38.95%-74.46% (readout, 15/26) and 62.12%-91.49% (lexical, 21/26). They do not fix label uncertainty, correlated cases or non-random development sampling. Under an appropriate independent binomial sampling model, even zero observed false positives requires at least 381 positive predictions for this interval's lower bound to reach 99%; this cohort cannot supply that evidence. A desired 99% point estimate and a 99% lower confidence bound are distinct claims.

The larger lexical check in [Lexical Scale Control](LEXICAL_SCALE_CONTROL.md) is predeclared separately. It tests all prepared train/validation assessments, including long sources, with the same classifier settings. It is not additional LLM training and cannot retroactively turn either result here into independent evidence.

Artifacts are under `training/runs/mac-frozen-probe-v1/`: `protocol.json`, numeric `features.npz`, `features.json`, `classifiers.json`, and `comparison.json`. Both methods and every failure remain available. The current evidence does not demonstrate that the 1.5B readout adds value over a simple lexical baseline; more parameters alone are not a demonstrated solution.
