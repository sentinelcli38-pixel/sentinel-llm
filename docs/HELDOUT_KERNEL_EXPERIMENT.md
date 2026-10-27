# Heldout Threshold Experiment

## Different Approach

Test nonlinear code similarity with a separately held-out training threshold pool. Earlier experiments chose operating points on OOF scores and then refitted a model on a larger pool; those operating points did not reliably transfer. This procedure instead freezes the fitted model **before** choosing its final threshold and never refits it afterward. This tests a procedural difference, not a proven explanation of earlier failures.

The target remains 99% precision, at least 80% recall and 80% specificity overall and per property. The stronger existing interval/support audit is unchanged. This is not LLM training, a semantic verifier, independent external evidence or a guaranteed 99% result. All previously inspected validation data remain development data for this iteration.

## Training Audit

`training-audit.json` checks the eligible training data without reading validation, prior comparisons or reserved tests. Exact source SHA + named target + property inputs have no mixed-label duplicates. Identifier/literal-normalized whole-source features can nevertheless collapse distinct labelled programs. Such collisions are not proof the professor/resource-person assessments are wrong; normalization can remove security-relevant distinctions. No label is automatically rewritten.

The audit also checks whether rows explicitly carry compiler and dependency-lock fields. Missing metadata is a source-context limitation, not proof of incorrect labels or unbuildable contracts. User-reported human approval remains recorded with written reports pending; preserved source reports keep their AI authorship. The independent-human consensus gate is unchanged.

## Frozen Roles

Reuse all 3,744 eligible training assessments and the original grouped anchor assignments:

| Role | Rows | Use |
| --- | ---: | --- |
| Model-fit pool: anchor folds 0/1 | 2,594 | Vocabulary/IDF fitting, grouped inner candidate selection, final model fitting |
| Threshold pool: anchor fold 2 | 1,150 | Final threshold only, after models are frozen |
| Development validation | 821 | One full-cohort frozen evaluation, then reproduction checks |

The original 22 unresolved training assessments remain withheld from fitting and retained in the prior review ledger; no evaluation cases are withheld. Known source/group/clone identities cannot cross roles, and every fitting/held group must retain both labels for every property. Abort rather than silently shrinking a property or dropping failures.

These are procedural roles within already accessible training data, not a claim that their annotations were historically unseen. The code passes only model-fit rows to the candidate-selection routine, and tests instrument vectorizer fitting/transforms to reject threshold-pool sources during model fitting. Stratified role/fold assignments necessarily use training label strata. Neither threshold-pool scores nor validation scores choose the candidate.

## Fixed Catalog

Four candidates per property, 16 total: normalized whole-source token 1-3 gram or case-sensitive raw character 3-5 gram TF-IDF, each with C=1 or C=10. Both have at most 8,192 features and row L2 normalization. All vocabulary/IDF fitting occurs strictly inside the applicable fitting subset. Character features retain names/compiler cues and can learn dataset shortcuts; whole-source features do not isolate a named target from unrelated declarations.

Use [scikit-learn SVC](https://scikit-learn.org/1.7/modules/generated/sklearn.svm.SVC.html), version 1.7.2, balanced class weights, a precomputed RBF kernel with gamma=1, tolerance 0.0001, and maximum 100,000 iterations. Compute each fold's similarity matrices once and reuse them across C settings. No stochastic probability-fitting CV is enabled. Solver/convergence failures abort and remain failures.

Within the model-fit pool only, use three global `StratifiedGroupKFold` folds, seed 811, grouping source families and stratifying property:label. Preserve every OOF decision margin for all candidates. Apply the existing precision-first selection rule at >=80% recall, with explicit failed-target fallback if no point qualifies. This is reused-OOF candidate selection, not nested/unbiased performance estimation.

Refit the selected procedure on **model-fit rows only** and save it before any threshold-pool scoring. `fitted.json` binds model bytes, candidate selection, all OOF evidence, code/data pins and dependency versions. Do not train on the threshold pool to make the model larger afterward.

Then transform threshold-pool inputs using that exact saved model and fit no new vocabulary or classifier. Choose each final threshold at the unchanged recall floor, retaining all threshold-pool labels and scores, including failed-target outcomes. Verify the model artifact hash is unchanged before and after this stage. The final threshold is not the provisional threshold used to rank inner-OOF candidates.

Margins are monotonically transformed by sigmoid and rounded to 12 decimals for stable threshold comparisons. These scores are **not calibrated probabilities of vulnerability**; the [calibration guide](https://scikit-learn.org/1.7/modules/calibration.html) distinguishes probability calibration from simply applying a sigmoid. The final decision uses score > frozen threshold, with negative ties. No threshold is adjusted on validation.

## Artifacts And Run

No new production or optional dependencies are required beyond the existing pinned scikit-learn environment. CPU only:

```bash
make model-prepare-heldout-kernel
make model-fit-heldout-kernel
make model-threshold-heldout-kernel
make model-evaluate-heldout-kernel
make test-heldout-kernel-runtime
```

The default output is `training/runs/mac-heldout-kernel-v1`. Existing directories and stage attempts are refused, not overwritten. Failures retain their own receipts. Models are deterministic gzip-compressed JSON containing sparse support vectors, dual coefficients, intercepts, vocabulary and IDF, never executable pickle. Replay is checked against sklearn's public precomputed-kernel decision function to 1e-10. Model hashes, complete threshold evidence and roles are verified before validation access; threshold tampering cannot bypass replay and recomputation.

All 821 validation labels/predictions remain in `comparison.json` with per-property metrics, the unchanged stronger target audit and a separate best-case sample-support audit. No model is promoted into the live detector. Smaller model-fit exposure, nonlinear kernels and separate threshold choice change together; any result would not isolate one causal benefit.

## Precision Evidence

An observed 99% precision point estimate differs from a nominal 95% interval whose lower bound is 99%. Under the existing two-sided Wilson rule, **381 correct positive flags with zero false positives** are the minimum for that lower bound. This is a mathematical sample-support requirement, not model performance. It does not establish independent source sampling, sound labels or external validity.

After model/threshold freezing, the support audit computes the most optimistic bound obtainable by correctly detecting every labelled validation positive with no false positives, both overall and per property. If even that bound is inadequate, it reports the limitation separately instead of changing the target, inventing examples, repeatedly counting correlated cases or calling a small perfect subset a 99% product.

## Results

Completed October 23, 2026. All 16 candidates completed three inner fitting folds. Every property selected the normalized-token representation, not raw characters: C=1 for SWC-101/115 and C=10 for SWC-104/107. All inner selections and final threshold choices are failed-target diagnostic fallbacks. No training or threshold statistic is presented as independent accuracy.

The separate 1,150-row threshold pool yields these selected operating points while model bytes remain unchanged:

| Property | Threshold cases | TP / FP / TN / FN | Selected precision | Selected recall |
| --- | ---: | --- | ---: | ---: |
| SWC-101 | 186 | 101 / 7 / 54 / 24 | 93.52% | 80.80% |
| SWC-104 | 328 | 50 / 46 / 220 / 12 | 52.08% | 80.65% |
| SWC-107 | 304 | 24 / 110 / 166 / 4 | 17.91% | 85.71% |
| SWC-115 | 332 | 11 / 1 / 319 / 1 | 91.67% | 91.67% |

These thresholds were selected using these labels and therefore are not an unbiased evaluation. They meet the selection recall floor but fail the precision target; reentrancy also fails specificity. No threshold was changed afterward.

### Full Validation

| Scope | Cases | TP / FP / TN / FN | Precision | Recall | Specificity |
| --- | ---: | --- | ---: | ---: | ---: |
| Overall | 821 | 100 / 106 / 534 / 81 | **48.54%** | **55.25%** | 83.44% |
| SWC-101 arithmetic | 162 | 57 / 6 / 30 / 69 | 90.48% | 45.24% | 83.33% |
| SWC-104 unchecked calls | 236 | 24 / 27 / 179 / 6 | 47.06% | 80.00% | 86.89% |
| SWC-107 reentrancy | 184 | 13 / 71 / 99 / 1 | 15.48% | 92.86% | 58.24% |
| SWC-115 origin authorization | 239 | 6 / 2 / 226 / 5 | 75.00% | 54.55% | 99.12% |

All 821 assessments remain in the denominator and produce valid-format classifier outputs. No format validity is represented as security proof. Both the all-property point-target check and stronger numerical target audit fail. The requested 99% precision is **not achieved**.

Against the immediately preceding structural attempt, precision improves from 43.72% to 48.54% and recall from 48.07% to 55.25%. Unchecked-call false positives decrease from 77 to 27, but reentrancy false positives increase from 29 to 71. This is a mixed development result, not universal improvement or proof of a threshold-transfer cause. The earlier grouped lexical control still has higher aggregate precision (60.39%) but lower recall (51.38%) than this run. The unweighted full-pool control remains better overall at 88.36%/71.27%, while missing every reentrancy and origin-authorization positive. None qualifies and none is silently replaced.

### Evidence Ceiling

Even the optimistic hypothetical of detecting every labelled validation positive with zero false positives cannot meet the existing 99% lower-interval-bound rule:

| Scope | Available labelled positives | Best-case nominal 95% lower precision bound | Extra perfect flags needed for nominal rule |
| --- | ---: | ---: | ---: |
| Overall | 181 | 97.92% | 200 |
| SWC-101 | 126 | 97.04% | 255 |
| SWC-104 | 30 | 88.65% | 351 |
| SWC-107 | 14 | 78.47% | 367 |
| SWC-115 | 11 | 74.12% | 370 |

This does **not** mean 99% observed precision is mathematically impossible on 821 cases. It means the stronger confidence-bound requirement cannot pass with current positive support, even under perfect decisions. The measured classifier also fails the weaker point target. Gathering more independent, consistently reviewed examples is necessary for stronger evidence but does not guarantee detector improvement, perfect predictions or a qualified claim. Duplicate, synthetic or correlated flags do not become independent evidence by increasing a counter.

### Audit Outcome

All 3,744 exact source/target/property inputs are unique, so no contradictory duplicate labels are found; this is not verification of any individual annotation. Normalized whole-source inputs form 3,276 buckets, including seven mixed-label buckets covering 19 rows. Lost identifiers, literals or requested-target distinctions can explain such collisions without incorrect human assessment. Every eligible row lacks an explicit per-row compiler-version/dependency-lock pair in its current schema. These context limitations remain unresolved; labels and source code are not automatically changed.

The live detector, 1.5B weights, original datasets, stricter independent-human review gate, previous reports and reserved tests are unchanged. Further progress needs genuinely better source-context/semantic evidence and independent validation, not a fabricated percentage or another threshold selected against these outcomes.

## Verification

568 Python tests pass. Twenty optional runtime checks skip in the main interpreter and all 20 pass separately in the isolated probe interpreter. Nineteen parser/dashboard tests pass. Targeted lint and whitespace checks pass. New tests cover role separation, fitting-transform instrumentation, kernel JSON replay on held inputs, deterministic compression, invalid sparse support vectors, solver failure retention, stage ordering, model immutability, threshold tampering, observed-point versus confidence-bound support, and output refusal after completed/failed attempts.

The actual model-fitting and threshold-stage audit hooks reject validation/test JSONL, previous comparison reports and cached AST/Qwen feature files. Classifier construction is trapped during threshold selection and evaluation. Model bytes are identical before/after threshold selection. These are local engineering checks, not externally authenticated attestations. Later reproduction checks do not constitute another independent evaluation.

Saved JSON replay reproduces all 821 reported margins, decisions and metrics exactly. Deterministic same-settings sklearn refits reproduce stabilized scores within 1.1e-12 and every decision identically; no new model choice or threshold is made. All 16 inner-OOF operating points, four heldout thresholds, the numerical target audit and support audit reproduce. Thirteen implementation/dependency source snapshots match their frozen hashes, all 65 pinned live-scanner implementation files are unchanged, and original dataset pins match. `verification.json` records these checks.

The evaluation stage opens validation JSONL once after the fitted-model and threshold receipts are complete. Reproduction checks later reread declared development data without tuning. No reserved test file is opened, hashed or tokenized. Completing these engineering checks does not qualify the failed model or establish a 99% security claim.
