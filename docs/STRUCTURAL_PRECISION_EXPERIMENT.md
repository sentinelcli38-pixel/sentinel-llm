# Contract-Scoped Structural Experiment

## Objective And Boundary

Improve the research classifier without changing the requested 99% precision, 80% minimum recall and 80% minimum specificity overall and for every property. Keep the stricter existing precision-interval and sample-support audit. No target is guaranteed in advance, no threshold is adjusted against validation outcomes, and no case is removed to improve a percentage.

This tests **syntactic AST features and contract-scoped tokens**, not LLM fine-tuning, verified semantic reasoning, interprocedural dataflow analysis, exploitability or production readiness. The 1.5B model and the live CLI/scanner are unchanged. Historical validation has already been inspected in earlier experiments, including the grouped lexical attempt; this new development iteration is not an independent external benchmark.

## Frozen Data

Reuse the exact training-only anchor from `mac-grouped-precision-v1`: the same 3,744 eligible training assessments, 856 source-family groups and three fold assignments. Preserve the original provisional review ledger, five copied training-label changes, and 22 unresolved training cases withheld from fitting only. All 64 reviewed observations remain available. Reported professor/resource-person approval remains user-reported with written reports pending; original AI authorship and the strict independent-human review gate are unchanged.

The anchor loader does not open prior comparison results, cached mixed-split Qwen features or validation JSONL. Original data and previous reports remain untouched. All 821 validation assessments retain their original labels and are scored only after a completed training-only fit receipt freezes models and thresholds. Reserved test JSONL files are never opened, hashed or tokenized.

## Feature Extraction

Use the isolated [Solidity Parser](https://github.com/solidity-parser/parser) version **0.20.2**, a published ANTLR-based parser. The npm lock pins its archive integrity; the protocol also pins the installed standalone bundle, package metadata, Node executable and Node version. Install scripts are disabled. The worker receives only source text, source SHA-256, named contract and an opaque source/target key through stdin. It never receives labels, predictions, dataset IDs or dataset paths, and never compiles or executes a contract.

Strict parsing must resolve the named target uniquely. Scoped lexical text contains that declaration plus unique in-file ancestor declarations, not unrelated sibling contracts. Target and base structural features have separate channels. Missing imported bases, modifier-name ambiguity and inheritance cycles are recorded. This is syntactic closure, **not** Solidity C3 dispatch or override resolution; all ancestor declarations remain visible rather than pretending they are all reachable entry points. Imported dependencies are not fetched or inferred.

Numeric features include:

- Function roles: external/public/default, internal/private and constructors, with mutability and Solidity type counts.
- AST node/parent-edge counts and arithmetic operators, including operations inside explicit unchecked blocks.
- Low-level calls, legacy `.gas()`/`.value()` and modern options, separating discarded expression results, stored results, returned results and direct guard/conditional usage. Storage of a result is not proof it was checked later.
- `tx.origin`, `msg.sender`, `msg.value` and syntactic guard/comparison contexts; matching text in comments and string literals does not create these AST features.
- Syntactic writes to named state roots and lexical order relative to calls, excluding names shadowed by function parameters/local declarations. This is not alias analysis, control-flow reachability or a proof of reentrancy.
- Applied in-file modifier syntax, unresolved modifiers, using-for declarations and explicitly named math methods/libraries. Familiar names such as SafeMath are cues, not proof their implementations are safe.
- Solidity pragma components as declared-source cues only, not a verified compiler version or resolved version constraint.

Per-function sums and maxima retain local co-occurrence instead of treating the whole file as one token bag. Feature names do not contain arbitrary source identifiers, target names, paths or labels. Token features use the existing identifier/literal normalizer and remove comments. Source ranges in worker metadata follow JavaScript/ANTLR string offsets.

Parse errors, recoverable parser-internal exceptions and missing/ambiguous targets remain explicit. Their predeclared fallback is whole-source lexical text plus an extraction-status feature where structural features are used. They are neither dropped nor automatically labelled clean. RangeError, process/resource failures and errors outside the parser call still abort the attempt and preserve a failure receipt rather than silently excluding a source.

For clarity, the structural-only tree family sees only the failure-status feature on such a source, not lexical text. The scoped-lexical and combined families can use the whole-source fallback text. A valid classifier output on a fallback case is not successful AST analysis; extraction coverage is reported separately from prediction-format validity.

## Candidate Catalog And Selection

Before scoring, freeze 18 candidates per property, 72 total:

| Family | Features | Fixed candidate variations |
| --- | --- | --- |
| Structural trees | Raw numeric AST features | 128 ExtraTrees, maximum depth 12, all features considered, leaf minimum 1/3/8, unweighted/balanced |
| Scoped lexical control | Named target/base normalized token TF-IDF | Logistic regression C=0.1/1/10, unweighted/balanced |
| Combined linear control | AST counts plus scoped token TF-IDF | Same logistic settings |

Use scikit-learn **1.7.2**, seed 617 and one tree worker. Linear heads use L2/liblinear, tolerance 0.0001 and maximum 5,000 iterations. Convergence warnings fail the attempt. The official classifier references are [ExtraTreesClassifier](https://scikit-learn.org/1.7/modules/generated/sklearn.ensemble.ExtraTreesClassifier.html) and [LogisticRegression](https://scikit-learn.org/1.7/modules/generated/sklearn.linear_model.LogisticRegression.html).

Every fold learns its own structural vocabulary and token vocabulary/IDF exclusively from its fitting rows. Trees see raw counts as float32. Combined linear inputs use log1p structural counts followed by row L2 normalization, token 1-3 gram TF-IDF with at most 16,384 features, and final row L2 normalization. Unknown held-input features are ignored, not added to fitted vocabularies. AST parsing itself is deterministic source processing, not a label-fitted transform.

Pool every out-of-fold positive-class model score for each candidate. Choose a threshold at recall >=80%. If all three point targets are feasible, maximize recall, precision, specificity, then stable candidate ID. Otherwise retain an explicitly failed-target fallback maximizing precision at the recall floor, then recall and specificity. Never lower the requested recall or select a property subset. Preserve all 18 candidate outcomes per property.

For numerical stability, version 4 rounds every OOF and replay score to 12 decimal places before threshold selection/comparison, ties numerically indistinguishable scores together, and permits clipping only floating overshoot within 1e-12 of [0,1]. Nonfinite values and genuine out-of-range scores remain failures. This is uniform across classes and candidates, not a validation-based threshold adjustment. Raw OOF scores remain alongside the stabilized scores; `oof-raw-<swc>.json` is written before operating-point selection, and both raw and selected evidence files are bound into the fit receipt.

This is training-only selection on reused OOF scores, not nested/unbiased CV. Refit each selected procedure on all eligible training rows with its OOF threshold unchanged. Positive-class scores and their shifted/sigmoid reporting transforms are **not calibrated probabilities of vulnerability**; score/threshold transfer may still fail. The three families change modeling and feature combinations together; their selection does not establish a causal AST-only benefit.

## Run And Evidence

The parser is optional and isolated from production Python dependencies:

```bash
make model-install-ast-parser
make test-ast-features
make test-structural-precision-runtime
make model-prepare-structural-precision
make model-fit-structural-precision
make model-evaluate-structural-precision
```

Existing attempts are refused, not overwritten. Preparation writes `protocol.json` before extraction or candidate scoring. Fit writes a source-target-deduplicated `training-features.json`, all OOF scores and labels, selected heads and a completion receipt with artifact hashes and runtime versions. Linear coefficients, IDF/vocabulary and tree arrays are JSON, never executable pickle. Saved model replay must reproduce sklearn scores to 1e-10 before fit completion. Tree replay preserves sklearn's float32 comparison input.

The actual version 4 run uses `--training-feature-cache training/runs/mac-structural-precision-v3` during preparation. This reuses only the source-only extraction completed by the previous stopped attempt. The new protocol pins its bytes and source protocol, verifies identical training inputs/IDs, parser worker hash and parser/Node runtime, and validates every source/target mapping. Model fitting, OOF scoring and selection are recomputed; no previous model or validation prediction is loaded. The optional cache is not necessary for a fresh run from source.

Evaluation verifies the completed fit and every frozen artifact before its first validation read. It records its own start, cached validation features with extraction coverage, every prediction and the unchanged target audit. Failure receipts remain visible, and no model is automatically deployed. Local access logs are engineering checks, not independently authenticated or OS-wide child-process attestations.

## Results

The original `mac-structural-precision-v1` attempt failed during training extraction, **before any candidate scoring or validation access**. The parser's AST builder raised a TypeError on WealthShare's legacy modifier placeholder without a trailing semicolon. The failure receipt and all 16 pinned implementation sources are retained under the original run and `reports/protocol-snapshots/structural-precision-v1/`. No failed source was dropped or rewritten.

Version 2 declared a separate `parser_internal_error` fallback for TypeErrors thrown specifically inside the parser call, with a regression test on the minimal legacy construct. It then stopped on a generic AST-builder `Error: Unrecognized expression`, also before candidate scoring or validation access. Its failure receipt and all 16 pinned sources remain under `mac-structural-precision-v2` and `reports/protocol-snapshots/structural-precision-v2/`.

Version 3 handles recoverable `Error` exceptions specifically within the third-party parser call, retaining their actual error kinds/messages. RangeError, process/resource failures and our own feature-extractor errors still abort. Both failure classes have minimal regression tests. Candidate catalog, data eligibility, grouped folds and quality targets are unchanged. The repaired attempt uses a fresh `mac-structural-precision-v3` directory and protocol; neither earlier failure is overwritten. A source-only compatibility inventory uses training sources only, not labels, candidate performance, validation or test data. No validation outcomes informed these compatibility repairs.

That inventory covers all 1,286 unique training source hashes: 1,145 parse directly; 140 raise recoverable parser-builder errors (139 TypeErrors and one generic Error), and one raises a normal ParserError. These are source-level counts, not property-row metrics, and not evidence that labels on fallback sources are clean or incorrect. `training/runs/mac-structural-parser-compatibility-v1/inventory.json` retains hashes, diagnostics and bounded source excerpts for compatibility work.

Version 3 completed extraction of all 3,744 eligible training assessments across 1,302 distinct source/target pairs: 3,248 parsed, 493 had explicit parser-internal errors, and three had syntax errors. It then stopped while choosing the SWC-101 operating point because adjacent floating-point scores had no representable midpoint under the strict threshold helper. No validation was accessed, no threshold or model was selected, and the failure receipt plus all 16 source snapshots are preserved. Candidate training folds had run, but their accuracy was not used to change hyperparameters or labels.

Version 4 declares the uniform score-stabilization policy above, adds regression checks for adjacent floating-point scores, and reuses the hash-pinned source-only cache. The same candidate catalog, data, grouped folds and targets are retained in a fresh `mac-structural-precision-v4` protocol. Its completed results are below. A completed run or passing engineering test is not evidence that the 99% quality target passed.

### Completed Measurement

Version 4 completed on October 23, 2026. All 72 candidates completed all three training folds. None could meet all requested training point targets, so all four selections are explicitly marked **failed-target diagnostic fallback**.

| Property | Selected candidate | OOF TP / FP / TN / FN | OOF precision | OOF recall |
| --- | --- | --- | ---: | ---: |
| SWC-101 | Combined linear, C=10, unweighted | 364 / 17 / 195 / 89 | 95.54% | 80.35% |
| SWC-104 | Structural trees, leaf minimum 3, unweighted | 156 / 79 / 773 / 32 | 66.38% | 82.98% |
| SWC-107 | Combined linear, C=10, balanced | 77 / 117 / 778 / 17 | 39.69% | 81.91% |
| SWC-115 | Combined linear, C=0.1, balanced | 40 / 3 / 999 / 8 | 93.02% | 83.33% |

These are training-selection statistics, not unbiased accuracy estimates. After freezing the four heads and thresholds, full validation yields:

| Scope | Cases | TP / FP / TN / FN | Precision | Recall | Specificity |
| --- | ---: | --- | ---: | ---: | ---: |
| Overall | 821 | 87 / 112 / 528 / 94 | **43.72%** | **48.07%** | 82.50% |
| SWC-101 arithmetic | 162 | 47 / 6 / 30 / 79 | 88.68% | 37.30% | 83.33% |
| SWC-104 unchecked calls | 236 | 22 / 77 / 129 / 8 | 22.22% | 73.33% | 62.62% |
| SWC-107 reentrancy | 184 | 13 / 29 / 141 / 1 | 30.95% | 92.86% | 82.94% |
| SWC-115 origin authorization | 239 | 5 / 0 / 228 / 6 | 100.00% | 45.45% | 100.00% |

All 821 cases produce valid classifier outputs; **719 parse directly and 102 retain explicit parser-internal-error fallback**. Classification-format validity must not be presented as 100% successful AST coverage. No validation source is excluded, relabelled or turned into an automatic true negative.

The overall result is **worse** than the immediately preceding grouped lexical attempt: precision falls from 60.39% to 43.72%, recall from 51.38% to 48.07%, and false positives rise from 61 to 112. Unchecked-call false positives rise from 18 to 77, despite apparently better training OOF selection statistics. Training selection did not transfer to this development cohort. These results do not causally establish whether source-family shift, threshold-score transfer, annotation conventions or insufficient syntactic reasoning dominate; they are not proof the professor/resource-person training assessments are wrong.

Origin authorization's five positive predictions are all labelled correct, but six of 11 labelled positives are missed. Its observed 100% precision is **not an achieved 99% product result**: recall is below 80%, support is tiny, the precision interval is inadequate and the broader properties fail. Reentrancy's precision improves modestly over the immediately preceding attempt, but loses one detected positive and remains far below target. Do not highlight either property without the overall regression.

The earlier unweighted full-pool lexical control remains better in aggregate at 88.36% precision and 71.27% recall, while missing every reentrancy and origin-authorization positive. It too is unqualified. No attempt is promoted simply because it is newer or uses more elaborate features. Both the version 4 all-property point-target check and the stronger unchanged numerical audit fail; independent 99% evidence remains unsupported. No LLM weights, validation labels or live detector rules change.

Further improvement needs evidence that the model generalizes under consistently scoped build/label assumptions. Repeatedly adjusting thresholds on these same validation outcomes would not establish that evidence. Preserve this failure alongside earlier controls rather than rewriting a percentage or suppressing difficult cases.

## Engineering Verification

554 Python tests pass. Fifteen optional dependency/runtime checks skip in the main interpreter and all 15 pass separately under the isolated probe interpreter. Nineteen Node tests pass: 14 parser/feature checks and five existing dashboard checks. Targeted lint and whitespace checks pass.

The checks include source-only worker inputs, exact target isolation from siblings, in-file base context, legacy and modern call syntax, direct result-use contexts, identifier-renaming invariance, local shadowing, constructor/internal-function separation, explicit parser fallbacks, resource/extractor error propagation, training-only vocabularies, complete OOF coverage, JSON tree/linear replay, score stability, cache reuse/pins, tampering and refusal to overwrite failed attempts. Synthetic fixture scores are not security benchmark results.

All 65 previously pinned scanner implementation hashes remain unchanged. Sixteen current implementation/dependency files match the version 4 source archive. The original dataset and earlier experiments remain intact. Test success establishes these engineering checks, not independent accuracy, source-build validity or a successful 99% quality gate.

Post-evaluation replay reproduces all 821 stored margins, predictions and metrics exactly. Separate deterministic refits with the same frozen selected settings reproduce every stabilized validation score with **zero difference** and identical decisions for all four properties. These refits verify preprocessing/serialization, not a new candidate selection or an independent evaluation. All 72 OOF operating points and the four selections reproduce from raw/stabilized training scores, and the unchanged target audit reproduces. Reused training feature bytes match their original pin. `verification.json` records the checks.

`extraction-diagnostics.json` retains post-evaluation descriptive status subsets only. Directly parsed cases have 44.22% precision and 42.48% recall (719 cases); fallback cases have 42.31% precision and 78.57% recall (102 cases). Poor performance on directly parsed cases means parser fallback alone cannot explain the failure. Neither subset is selected for a headline score or removed from the primary 821-case denominator.

The actual training access log records no forbidden parent-process validation/test/cache/comparison access. The evaluation access log records one validation JSONL open after fit completion; later reproduction checks read the declared development data again without choosing a new model or threshold. Parent audit hooks are not independently authenticated or OS-wide attestations. No reserved test JSONL was opened, hashed or tokenized.
