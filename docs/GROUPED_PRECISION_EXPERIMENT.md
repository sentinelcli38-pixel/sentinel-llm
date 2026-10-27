# Grouped Precision Experiment

## Objective

Try a stronger lexical control while keeping the requested **99% precision, at least 80% recall and 80% specificity overall and for every property**. A small high-precision queue that misses most positives does not satisfy this target. The stricter existing audit also requires nominal 95% precision interval lower bounds of 99% and sufficient positive/negative support. Development point estimates cannot establish independent production performance.

This is **not** a new 1.5B LLM result, LoRA update or scanner release. It tests whether richer local code-pattern features and training-only selection improve on earlier fixed unigram controls. No base-model weights, detector rules, test files, original datasets or historical reports are modified.

## Data And Review Provenance

Use the full 3,766-row training pool with the previously frozen provisional review overlay: 3,744 eligible training assessments, five copied SWC-104 label changes, and 22 unresolved training cases withheld from fitting only. All 64 review decisions remain in the ledger. Original submissions retain AI authorship and user-reported professor/resource-person approval with written reports pending. This does not convert them into independently authenticated human consensus or executable ground truth.

The selection reader opens only training JSONL and the pinned manifest. It verifies source hashes, prompt targets, row identities, preserved review bytes, original training-selection metadata and recomputed review decisions. It does not load cached Qwen features, prior comparisons, validation rows or reserved tests. The original broad dataset reader is called only after the selected model and thresholds have been frozen.

Evaluation uses all **821 development validation assessments**, unchanged labels and no confidence-based exclusions. These data have already been inspected in previous development; they are not a fresh independent benchmark. Comparisons with earlier full-pool results are descriptive: data eligibility, representations, class weighting and selection procedures differ. They do not isolate a single causal improvement.

## Frozen Selection Procedure

Before candidate scoring, `protocol.json` freezes the full training IDs, grouped folds, candidate catalog, source-code hashes and review provenance:

- Three global `StratifiedGroupKFold` folds, seed 617, stratifying property:label and grouping by `project_group`. Source hashes and declared normalized-clone fingerprints must also stay in one fold. Both labels must occur for every property in every fitting and held fold; otherwise abort.
- Two representations per property: identifier/literal-normalized word n-grams of length 1-3, and case-sensitive raw character n-grams of length 3-5. Both use L2 TF-IDF and at most 16,384 features. Every fold fits its own vocabulary and IDF on fitting rows only. Character features retain compiler versions, comments and names; these can carry annotation/dataset shortcuts, not semantic security reasoning.
- Six linear SVM settings per representation: C = 0.1, 1, 10, each unweighted or class-balanced. `LinearSVC`, scikit-learn 1.7.2, automatic dual selection, L2 squared-hinge defaults, tolerance 0.0001, maximum 20,000 iterations. Convergence warnings abort rather than quietly dropping failed candidates.
- Retain all 12 candidates per property and every out-of-fold training margin. Thresholds lie between distinct scores; ties remain together. Only thresholds with recall >=80% are eligible.
- If a candidate/threshold meets all three training point targets, maximize recall, then precision, specificity and stable candidate ID. Otherwise explicitly record **failed-target diagnostic fallback**, maximizing precision at the required recall, then recall, specificity and stable ID. The requested target is not relaxed.
- Refit each selected representation/head on all eligible training examples and retain its selected OOF threshold. This assumes margins transfer sufficiently from fold fits to the full fit; they are not calibrated probabilities and transfer can fail. No threshold correction on validation is allowed.

Pooled out-of-fold margins are used for both candidate and threshold selection. This is training-only model selection, **not nested CV or an unbiased performance estimate**. Grouping controls known source/clone leakage, not every possible semantic similarity, shared-library relationship or upstream annotation problem. No claim of pretraining independence follows.

The official implementation references are [StratifiedGroupKFold](https://scikit-learn.org/1.7/modules/generated/sklearn.model_selection.StratifiedGroupKFold.html), [LinearSVC](https://scikit-learn.org/1.7/modules/generated/sklearn.svm.LinearSVC.html), and [TfidfVectorizer](https://scikit-learn.org/1.7/modules/generated/sklearn.feature_extraction.text.TfidfVectorizer.html). Word n-grams use a custom **tokenizer**, not a callable analyzer that would bypass the n-gram setting.

## Execution And Artifacts

Use the existing isolated optional dependencies in `training/requirements-probe.txt`; nothing is added to production dependencies. CPU only:

```bash
make model-prepare-grouped-precision
make model-fit-grouped-precision
make model-evaluate-grouped-precision
make test-grouped-precision-runtime
```

The default output is `training/runs/mac-grouped-precision-v1`. An existing output directory, fit attempt or evaluation attempt is refused; retain failed outcomes instead of overwriting them. For a genuinely new research protocol, declare its changes before scoring and use a fresh directory. Do not repeat development selection until a favorable percentage appears.

`oof-101.json`, `oof-104.json`, `oof-107.json` and `oof-115.json` retain every candidate's training margins, labels and selected operating point. `models.json` stores vocabulary, IDF, coefficients and intercepts as JSON, not executable pickle. Training replay must reproduce sklearn margins to 1e-10 before a fit can complete.

`selection.json` records all selected models and failed-target fallbacks. `fit.json` binds every completed artifact and dependency version before evaluation can open validation. `evaluation-started.json` binds that receipt before the first validation read; failures are retained separately. `comparison.json` preserves all 821 predictions, original labels, per-property metrics, point-target checks and the unchanged stronger audit. No model is promoted into the live scanner.

## Results

Completed October 23, 2026. All 48 candidates (12 per property) completed their three training folds, followed by four full-training refits. The 3,744 training rows span 856 source-family groups; held-fold sizes are 1,255, 1,339 and 1,150. No candidate could meet all requested point targets on training OOF evidence. All four selected heads are explicitly marked **failed-target diagnostic fallback**, not successful 99% models.

| Property | Selected representation / C / weight | OOF TP / FP / TN / FN | OOF precision | OOF recall |
| --- | --- | --- | ---: | ---: |
| SWC-101 | Tokens / 0.1 / balanced | 364 / 17 / 195 / 89 | 95.54% | 80.35% |
| SWC-104 | Tokens / 1 / unweighted | 151 / 123 / 729 / 37 | 55.11% | 80.32% |
| SWC-107 | Tokens / 10 / unweighted | 77 / 91 / 804 / 17 | 45.83% | 81.91% |
| SWC-115 | Characters / 10 / balanced | 39 / 1 / 1001 / 9 | 97.50% | 81.25% |

These are selection statistics, not unbiased generalization estimates. After freezing all four JSON models and thresholds, the single full-cohort development evaluation yields:

| Scope | Cases | TP / FP / TN / FN | Precision | Recall | Specificity |
| --- | ---: | --- | ---: | ---: | ---: |
| Overall | 821 | 93 / 61 / 579 / 88 | **60.39%** | **51.38%** | 90.47% |
| SWC-101 arithmetic | 162 | 50 / 2 / 34 / 76 | 96.15% | 39.68% | 94.44% |
| SWC-104 unchecked calls | 236 | 23 / 18 / 188 / 7 | 56.10% | 76.67% | 91.26% |
| SWC-107 reentrancy | 184 | 14 / 39 / 131 / 0 | 26.42% | 100.00% | 77.06% |
| SWC-115 origin authorization | 239 | 6 / 2 / 226 / 5 | 75.00% | 54.55% | 99.12% |

All 821 assessments produce valid predictions. Both the all-property point-target check and the stronger unchanged numerical audit fail. Even the 96.15% arithmetic precision is below 99% and comes with inadequate recall. Detecting all 14 reentrancy positives also produces 39 false positives; do not report its recall without that precision failure. The 14 reentrancy and 11 origin-authorization positives are below the audit's minimum support of 20 per property.

Training OOF operating points do not transfer uniformly to this validation cohort. Causes could include score-scale changes from fold fits to full fits, source-family distribution differences, label noise or annotation conventions; this run does not causally identify which. No validation-based adjustment is performed to disguise the mismatch.

The new model does **not** outperform every earlier control. The earlier unweighted unigram control had 88.36% precision and 71.27% recall overall, but zero recall for reentrancy and origin authorization. The latest provisional balanced unigram control had 44.44% precision and 50.83% recall. Those results remain alongside this one; the richer procedure is not a qualified replacement simply because it is newer. None meets the all-property target, and none of these lexical results is evidence of improved 1.5B LLM performance.

Raw SVM margins and their sigmoid transform are not calibrated probabilities of vulnerability. Written review reports, consistent independently reviewed evaluation labels and an external benchmark remain distinct evidence needs, not missing values to invent. The next scientifically useful change is a separately declared experiment in contract-scoped structural/semantic features and consistently reviewed training contrasts, not another threshold adjustment against these validation outcomes. Its success cannot be guaranteed in advance.

## Verification

529 Python tests pass; eight optional runtime checks skip in the main interpreter and all eight pass separately in the isolated probe interpreter. All five dashboard tests pass. New tests cover validation/test access guards, complete grouped fold coverage, both-label requirements, tied scores, infeasible targets without recall relaxation, deterministic selection, actual word n-gram generation, JSON reconstruction, tamper rejection, convergence failure and refusal to overwrite attempts. Targeted lint and whitespace checks pass.

During the actual preparation and fitting run, a Python audit hook rejected every attempted validation/test JSONL, mixed-split feature cache or earlier comparison open. `selection-access-audit.json` records successful completion without forbidden access. The evaluation audit records one validation JSONL open only after the fit receipt was frozen and no reserved test access. These local access logs are engineering evidence, not independently authenticated attestation.

After scoring, saved JSON models replay all **821 validation margins, predictions and metrics exactly**. All 48 OOF operating points and four selected models also reproduce from preserved training evidence. This verification does not refit a model, choose a new threshold or create an additional independent evaluation. The target audit reproduces, original dataset pins remain unchanged, and all 65 pinned scanner implementation hashes are unchanged. Eleven implementation source files are archived under `reports/protocol-snapshots/grouped-precision-v1/`; `verification.json` records these checks. No reserved model test file is opened and no failed candidate is promoted.
