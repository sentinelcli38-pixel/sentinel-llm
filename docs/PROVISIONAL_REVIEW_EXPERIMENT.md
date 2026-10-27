# Provisional Review Experiment

## Approval And Scope

On October 23, 2026, the user reported that their professor and resource person consider the two submitted reviews correct, authorized continuing work, and said written reports would follow after some days. We record this as **user-reported approval, written reports pending**. No identities, institutional IDs, signatures, completed reports, original-build verification or independently authenticated review coverage have been supplied or invented.

The two source reports retain their declared AI authorship. They are used as provisional, AI-assisted source assessments for an opt-in development experiment. They are not silently converted into human submissions, independent blind consensus, executable security ground truth or production approval. The original stricter `scripts/label_review.py` human-consensus validator remains unchanged. Written reports can later be retained with new provenance and an explicitly documented coverage/method; do not rewrite these original artifacts or backdate sign-off.

## Training Ledger

All **64 training assessments** remain in `review-decisions.json` with original historical labels, opaque review IDs, source pins, both decisions and provenance:

- 42 matching definite decisions (10 positive, 32 negative) can enter provisional training.
- Nine disagreements and 13 shared unknowns remain unresolved. These 22 cases are withheld from the provisional **training loss**, not relabelled clean or removed from an evaluation denominator.
- Five of the 42 agreements differ from the historical label: Omnipurse, Store and KobyShop become provisionally negative; Sweeper and BCFSafe become provisionally positive for SWC-104 only. These are provisional source-assessment changes, not demonstrated exploitability or whole-contract safety.

The agreement policy is deliberately conservative, not a claim that two AI outputs provide independent proof. Unknown/context-dependent cases and the exclusion of difficult examples can affect learned behavior. Retain that selection effect and the original historical control in every comparison. Unreviewed training cases outside this 64-case packet keep their existing historical labels. The separate validation reviews are not inferred from these training decisions.

## Fixed Experiment

Before scoring, freeze seed 419; per-property L2/liblinear logistic regression; C=1; tolerance 0.0001; maximum 2,000 iterations; intercept enabled; `class_weight="balanced"`; and threshold 0.5 with negative ties. Pin scikit-learn 1.7.2. Abort on convergence failure. No threshold, checkpoint, feature or hyperparameter search is performed.

Retain all six arms, rather than selecting whichever looks best:

| Representation | Historical training | Provisional training | Unchanged validation |
| --- | ---: | ---: | ---: |
| Frozen Qwen 1.5B last-token features | 200 | 178 | 54 |
| Matched-pool lexical TF-IDF control | 200 | 178 | 54 |
| Full-pool lexical TF-IDF control | 3,766 | 3,744 | 821, plus the declared original 54-case subset |

Each historical/provisional pair uses the same balanced-class procedure. Class weights are computed from that arm's training labels only. This permits a comparison of the review overlay under a fixed weighting rule; label changes and withholding uncertain cases are jointly changed and are not causally separated. The earlier unweighted experiments remain untouched for historical comparison.

The readout reuses hash-pinned cached representations from the verified 1,543,714,304-parameter base. It fits small classification heads, **not** all base parameters or a new LoRA adapter. Cached matrix dimensions, IDs, feature receipts, finite values, source-run evidence and code pins are checked. No new Metal inference is needed.

Lexical vocabulary and IDF are fitted exclusively on the applicable training sources, with identifier/literal-normalized unigrams and at most 4,096 features per property. Full-pool lexical results have greater data exposure and are not LLM performance. Validation is never used to choose vocabulary, class weights or thresholds. All historical validation labels and all 54/821 intended predictions are retained. The overlapping cohorts and six arms are not independent replications.

## Run

Use the existing isolated optional probe dependencies:

```bash
.venv/bin/python training/provisional_review.py prepare --experimental \
  --output training/runs/mac-provisional-review-v1

.venv-mlx/bin/python -u training/provisional_review.py score --experimental \
  --output training/runs/mac-provisional-review-v1
```

Existing output directories and stage artifacts are refused. Preparation preserves exact raw copies of A, B, packet, original manifest and mapping; their source paths are recorded but later changes to those original submission files cannot rewrite the preserved evidence. Loading recomputes the complete ledger from preserved evidence and the pinned training pool. Merely updating a ledger hash after editing a label does not bypass the reconciliation rule.

The protocol is written before classifier scoring. `execution.json` records this experiment's own completion or failure; `comparison.json` retains every arm, all predictions, per-property metrics, numerical target checks, nominal precision intervals and pending approval status. Classifier coefficients and preprocessing are stored as non-executable JSON. No source contract is executed, patched or uploaded. Reserved model test files remain unopened, and the live CLI/scanner is unchanged.

## Claim Boundary

The old 99% target audit is applied to each new arm without weakening its per-property precision, recall, specificity or sample-support requirements. Its independent-evidence flag remains false. Validation annotations and compiler/dependency context have not become verified merely because training reviews were approved as reported by the user. No 99% accuracy or precision claim follows from this experiment, regardless of a favorable point estimate.

## Measured Results

Completed October 23, 2026. All six arms completed. Each row compares a fixed class-balanced historical control with the provisional overlay under the same classifier settings and unchanged validation cohort:

| Family / arm | Training | Validation | TP / FP / TN / FN | Precision | Recall |
| --- | ---: | ---: | --- | --- | --- |
| Frozen Qwen / historical | 200 | 54 | 15 / 11 / 21 / 7 | 57.69% | 68.18% |
| Frozen Qwen / provisional | 178 | 54 | 15 / 15 / 17 / 7 | 50.00% | 68.18% |
| Matched lexical / historical | 200 | 54 | 21 / 5 / 27 / 1 | 80.77% | 95.45% |
| Matched lexical / provisional | 178 | 54 | 20 / 11 / 21 / 2 | 64.52% | 90.91% |
| Full lexical / historical | 3,766 | 821 | 93 / 110 / 530 / 88 | 45.81% | 51.38% |
| Full lexical / provisional | 3,744 | 821 | 92 / 115 / 525 / 89 | 44.44% | 50.83% |

The provisional overlay does **not** improve agreement with the unchanged historical validation annotations in any of the three comparisons. The other properties' heads are isolated from this SWC-104-only overlay; the differences within each family concern SWC-104. Its frozen-Qwen precision falls from 6/7 to 6/11 positive predictions at unchanged recall 6/8; matched lexical precision falls from 8/8 to 7/13 and recall from 8/8 to 7/8. All these small-sample figures remain development observations.

Balancing the full training pool has a separate tradeoff versus the earlier unweighted full-pool experiment. Reentrancy recall rises from 0/14 to 13/14 and origin-authorization recall from 0/11 to 7/11. However, arithmetic recall falls from 123/126 to 53/126, and false positives rise substantially. Neither balancing alone nor the provisional overlay meets the requested all-property quality target. Do not present one rare-property improvement without the arithmetic losses, or compare the 821-case lexical results as if they were LLM performance.

All six numerical 99%-target audits fail. No model was selected or promoted into the live scanner. Nominal precision intervals, every prediction, balanced training counts/weights, the 54-case subsets of full-pool evaluation and pending-approval provenance remain in `training/runs/mac-provisional-review-v1/comparison.json` and `classifiers.json`.

Lower agreement with the old validation annotations is not proof that the professor/resource-person assessments are wrong. Training labels, unknown-case eligibility, class weights and annotation conventions can interact; the validation cases have not received the same review. Conversely, reported approval of training cases does not make poor held-out decisions reliable. Keep this result and obtain a consistently scoped, independently reviewed evaluation before drawing stronger conclusions. Do not change validation labels solely to improve these percentages.

## Verification

507 Python tests pass. Four optional-dependency runtime checks are skipped in the main interpreter and pass separately in the isolated probe interpreter; all five dashboard tests pass. The new tests cover exact packet identity, complete case coverage, hash/source/property isolation, unknown/pending withholding, copied label changes, preservation of AI identity, explicit pending-report provenance, tampering and output immutability. Targeted lint and whitespace checks pass.

The generated classifiers are replayed from saved JSON against all 1,858 primary validation predictions across the six arms, and the overlapping full-pool 54-case subsets are checked separately. Historical matched controls reproduce the earlier readout and lexical-control metrics. Source snapshots for the ten implementation files are retained under `reports/protocol-snapshots/provisional-review-v1/`. Original reports, datasets, base weights, stricter human consensus validation and default product behavior are unchanged; reserved model test files remain unopened.
