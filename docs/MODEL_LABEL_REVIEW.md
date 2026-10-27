# Model Label Review And Contrast Preparation

## What Changed

The failed binary experiment now has a reproducible, CPU-only review preparation stage. It verifies the saved run using the existing diagnostic audit, retains **all 54 selected validation cases**, and prepares a separate **64-case SWC-104 training packet**. Training and validation sources are not mixed. No reserved test file is opened, no model is trained, no threshold is selected and no label is changed.

The 64 cases are the entire frozen selected SWC-104 training pool, not necessarily examples all seen during the original 64 training steps. Original exposure is retained per case in administrator provenance. Historical upstream assessments, original source URLs, source/project identities and exact embedded-source hashes are preserved. Sources are the model-visible comment-stripped representations, not silently repaired contracts or original comment-bearing files. Compiler versions and dependency closure remain unverified; reviewers must use unknown when necessary.

## Prepared Artifacts

Completed October 22, 2026, under `reports/label-review/binary-v1/`:

| Artifact | Purpose |
| --- | --- |
| `validation/blind/` | All 54 validation assessments; two blank reviewer forms |
| `training/blind/` | All 64 training assessments; two blank reviewer forms |
| `training-contrast-candidates.json` | Administrator-only list of 32 candidate pairs |
| `validation-manifest.json`, `training-manifest.json` | Original labels/provenance; not for the initial blind pass |
| `verified-original-diagnostic.json` | Verified evidence from the failed model run |
| `sources/` | Hash-pinned, exact model-visible source copies |
| `preparation.json` | Counts, implementation/input artifact hashes and explicit not-reviewed status |

The validation denominator is unchanged: SWC-101 has 8 historical positives and 8 negatives; SWC-104 has 8 and 8; SWC-107 has 5 and 8; SWC-115 has 1 and 8. These inspected development cases are not an independent benchmark. No cases were chosen by prediction success or removed for missing context.

Pair preparation greedily matches opposite historical training labels by descending identifier/literal-normalized five-token shingle Jaccard similarity, with deterministic ID tie-breaks and no case reuse. Same source hash, project group or lexical fingerprint cannot form a pair. All 64 cases are retained in the training review packet, including any that cannot be paired. In this run all 64 formed 32 pairs; none were added from validation.

Lexical similarity is only a review-organizing heuristic. There is no minimum similarity guarantee, optimal-matching claim, semantic equivalence, causal single-change intervention, new independent sample or verified defect label. Neither side of a pair is automatically approved training data. Pair suggestions remain outside `blind` to avoid telling reviewers which historical label to expect.

Measured pair similarities range from **0.0000 to 0.1557**. These are weak lexical matches, including a zero-overlap pair, not a ready-made high-quality contrastive dataset. The limited frozen pool does not supply close opposite-label examples under this measure. Retain this outcome rather than renaming the pairs as hard negatives or using their proximity as evidence for labels. Reviewed, diverse training data still needs to be assembled before a new contrastive training experiment.

## Human Handoff

1. Give each of two independent qualified reviewers only the relevant cohort's `blind` folder and [Independent Source Review](MODEL_REVIEW_INSTRUCTIONS.md). Training and validation may be reviewed by different pairs of people. Do not provide the administrator manifests, contrast candidates or predictions during the first pass.
2. Reviewers complete their own form with actual identity/qualifications, case-specific rationale and source evidence. Preserve initial submissions; use separate files for reconciled revisions. Missing context, disagreement and unfinished decisions remain visible, not negative labels.
3. Import completed forms into a **new** consensus directory, separately for each cohort:

```bash
.venv/bin/python scripts/label_review.py consensus \
  reports/label-review/binary-v1/validation \
  --reviewer-a /absolute/path/completed-validation-a.json \
  --reviewer-b /absolute/path/completed-validation-b.json \
  --output reports/label-review/binary-v1-validation-consensus

.venv/bin/python scripts/label_review.py consensus \
  reports/label-review/binary-v1/training \
  --reviewer-a /absolute/path/completed-training-a.json \
  --reviewer-b /absolute/path/completed-training-b.json \
  --output reports/label-review/binary-v1-training-consensus
```

The untouched forms are deliberately rejected. Only matching positive/negative decisions become consensus labels; unresolved cases remain unknown and originals stay in provenance. Do not run these uncompiled source-review manifests as if they were buildable scanner projects, automatically overwrite the original training dataset, or report precision over only the agreed subset without coverage and unresolved counts.

## Reproduce

```bash
make model-prepare-review MODEL_REVIEW_OUTPUT=reports/label-review/binary-v1-rerun
```

Use the main `.venv`, not the minimal MLX interpreter. Equivalent:

```bash
.venv/bin/python training/prepare_model_review.py \
  --run training/runs/mac-binary-v1 --dataset datasets/model-properties \
  --output reports/label-review/binary-v1-rerun
```

Existing outputs and paths inside the frozen run/dataset are refused. `preparation.json` is written last; a directory without it is incomplete. Integrity hashes bind local files at preparation time, not authenticated historical authorship. Local review copies remain subject to the upstream sources' individual licenses; preparation does not authorize redistribution.

## Remaining Gate

Current status is **prepared, not human-reviewed**. The adapter is still unqualified and its precision remains unavailable because it predicts no positives. Preparing data does not improve those results. The next training protocol should be specified only after reviewing label/context issues and should retain all failed outcomes. Any future 99% precision claim needs adequate sample support, recall/coverage reporting, uncertainty, contamination controls and a genuinely independent external assessment. Neither these development cases nor a new threshold fitted to their scores provides that evidence.

That preparation status records the October 22 artifact state. On October 23, the user reported professor/resource-person approval of the two AI-assisted training reviews, with written reports to follow, and authorized proceeding. The separate [provisional review experiment](PROVISIONAL_REVIEW_EXPERIMENT.md) now preserves that pending-documentation provenance, keeps all 64 review cases visible, and uses 42 matching definite training observations without altering these original packets or calling them signed human consensus. The 54-case validation review is not covered by the training approvals.

## Verification

444 Python tests and five dashboard tests pass. Targeted lint and tracked whitespace checks pass. All 250 generated artifact hashes and three preparation implementation hashes match the receipt, and all 65 frozen scanner implementation pins are unchanged. Source snapshots for the new preparation script and updated review helper are retained under `reports/protocol-snapshots/model-review-v1/`. No model weights, historical labels, thresholds, original reports or default scanner behavior changed; reserved model test files remain unopened.
